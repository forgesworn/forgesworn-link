//! The browser relay socket: the page's `WebSocket`, binary type
//! `arraybuffer`.
//!
//! This is the whole of a browser's network reach.  It speaks only to a Link
//! relay, only over `wss://`, and only with the browser's own WebPKI
//! verification; `RelaySpec::browser_url` refuses anything else before a
//! socket is opened.

use std::cell::RefCell;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};

use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

use super::WsMessage;
use super::inbound::{InboundQueue, MAX_MESSAGE_BYTES};
use crate::relay_client::RelaySpec;

/// `bufferedAmount` above which the session stops taking datagrams off its
/// queue.  A browser WebSocket never pushes back on `send`, so without this
/// the relay queue's backpressure would end in the page's buffer instead of
/// at quinn.
const SEND_HIGH_WATER: u32 = 1 << 20;

#[derive(Default)]
struct Shared {
    open: bool,
    ended: Option<String>,
    queue: InboundQueue,
    waker: Option<Waker>,
}

impl Shared {
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn end(&mut self, reason: String) {
        if self.ended.is_none() {
            self.ended = Some(reason);
        }
        self.wake();
    }
}

/// How soon a session whose socket was not `send_ready` looks again.
pub fn send_retry() -> impl std::future::Future<Output = ()> {
    crate::rt::sleep(std::time::Duration::from_millis(10))
}

pub struct RelaySocket {
    ws: WebSocket,
    shared: Rc<RefCell<Shared>>,
    _on_open: Closure<dyn FnMut(Event)>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
}

impl RelaySocket {
    pub async fn open(spec: &RelaySpec) -> anyhow::Result<RelaySocket> {
        let url = spec.browser_url()?;
        let ws = WebSocket::new(&url)
            .map_err(|e| anyhow::anyhow!("the browser refused the relay WebSocket: {e:?}"))?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let shared = Rc::new(RefCell::new(Shared::default()));

        let on_open = {
            let shared = shared.clone();
            Closure::<dyn FnMut(Event)>::new(move |_: Event| {
                let mut shared = shared.borrow_mut();
                shared.open = true;
                shared.wake();
            })
        };
        let on_message = {
            let shared = shared.clone();
            let ws = ws.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let mut shared = shared.borrow_mut();
                if shared.ended.is_some() {
                    return;
                }
                let message = match event.data().dyn_into::<js_sys::ArrayBuffer>() {
                    Ok(buffer) if buffer.byte_length() > MAX_MESSAGE_BYTES => {
                        let _ = ws.close();
                        shared.end("relay message above the frame bound".into());
                        return;
                    }
                    Ok(buffer) => WsMessage::Binary(js_sys::Uint8Array::new(&buffer).to_vec()),
                    Err(_) => WsMessage::Other,
                };
                if !shared.queue.push(message) {
                    let _ = ws.close();
                    shared.end("relay control frames arrived faster than they were read".into());
                    return;
                }
                shared.wake();
            })
        };
        let on_error = {
            let shared = shared.clone();
            // A browser deliberately reports nothing about why a WebSocket
            // failed, so there is no detail to keep.
            Closure::<dyn FnMut(Event)>::new(move |_: Event| {
                shared.borrow_mut().end("WebSocket error".into());
            })
        };
        let on_close = {
            let shared = shared.clone();
            Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
                shared
                    .borrow_mut()
                    .end(format!("closed with code {}", event.code()));
            })
        };
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        // Built before the wait, so a caller's timeout that drops this
        // future closes the socket.
        let socket = RelaySocket {
            ws,
            shared,
            _on_open: on_open,
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
        };
        poll_fn(|cx| {
            let mut shared = socket.shared.borrow_mut();
            if shared.open {
                Poll::Ready(Ok(()))
            } else if let Some(reason) = &shared.ended {
                Poll::Ready(Err(anyhow::anyhow!(
                    "relay WebSocket did not open: {reason}"
                )))
            } else {
                shared.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await?;
        Ok(socket)
    }

    /// Whether the session should take another datagram off its queue.
    /// Checked before a datagram is sent, never waited on inside `send`, so
    /// the session keeps reading while the page's send buffer drains.
    pub fn send_ready(&self) -> bool {
        self.ws.buffered_amount() <= SEND_HIGH_WATER
    }

    /// Sends at once.  Backpressure is `send_ready`'s, applied only to
    /// datagrams; a ping or registration is small and always goes.
    pub async fn send(&mut self, bytes: Vec<u8>) -> anyhow::Result<()> {
        if let Some(reason) = &self.shared.borrow().ended {
            anyhow::bail!("relay WebSocket ended: {reason}");
        }
        self.ws
            .send_with_u8_array(&bytes)
            .map_err(|e| anyhow::anyhow!("relay send failed: {e:?}"))
    }

    pub async fn next(&mut self) -> Option<anyhow::Result<WsMessage>> {
        poll_fn(|cx| {
            let mut shared = self.shared.borrow_mut();
            if let Some(message) = shared.queue.pop() {
                Poll::Ready(Some(Ok(message)))
            } else if shared.ended.is_some() {
                Poll::Ready(None)
            } else {
                shared.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }
}

impl Drop for RelaySocket {
    fn drop(&mut self) {
        self.ws.set_onopen(None);
        self.ws.set_onmessage(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}
