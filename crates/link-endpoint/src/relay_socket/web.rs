//! The browser relay socket: the page's `WebSocket`, binary type
//! `arraybuffer`.
//!
//! This is the whole of a browser's network reach.  It speaks only to a Link
//! relay, only over `wss://`, and only with the browser's own WebPKI
//! verification; `RelaySpec::browser_url` refuses anything else before a
//! socket is opened.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Duration;

use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

use super::WsMessage;
use crate::relay_client::RelaySpec;

/// Received messages held for the relay session.  The page delivers them
/// whether or not the session keeps up, so the bound is enforced here: a
/// relay that outruns the session loses the session rather than growing
/// the queue.
const INBOUND_BOUND: usize = 1024;
/// `bufferedAmount` above which a send waits.  A browser WebSocket never
/// pushes back on `send`, so without this the relay queue's backpressure
/// would end in the page's buffer instead of at quinn.
const SEND_HIGH_WATER: u32 = 1 << 20;
const SEND_POLL: Duration = Duration::from_millis(10);

#[derive(Default)]
struct Shared {
    open: bool,
    ended: Option<String>,
    queue: VecDeque<WsMessage>,
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
                if shared.queue.len() >= INBOUND_BOUND {
                    let _ = ws.close();
                    shared.end("relay messages arrived faster than they were read".into());
                    return;
                }
                let message = match event.data().dyn_into::<js_sys::ArrayBuffer>() {
                    Ok(buffer) => WsMessage::Binary(js_sys::Uint8Array::new(&buffer).to_vec()),
                    Err(_) => WsMessage::Other,
                };
                shared.queue.push_back(message);
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

    pub async fn send(&mut self, bytes: Vec<u8>) -> anyhow::Result<()> {
        loop {
            if let Some(reason) = &self.shared.borrow().ended {
                anyhow::bail!("relay WebSocket ended: {reason}");
            }
            if self.ws.buffered_amount() <= SEND_HIGH_WATER {
                break;
            }
            crate::rt::sleep(SEND_POLL).await;
        }
        self.ws
            .send_with_u8_array(&bytes)
            .map_err(|e| anyhow::anyhow!("relay send failed: {e:?}"))
    }

    pub async fn next(&mut self) -> Option<anyhow::Result<WsMessage>> {
        poll_fn(|cx| {
            let mut shared = self.shared.borrow_mut();
            if let Some(message) = shared.queue.pop_front() {
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
