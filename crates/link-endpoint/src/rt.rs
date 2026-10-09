//! The runtime seam: spawning, timers, the clock and quinn's runtime.
//!
//! Protocol logic in this crate is written once against these functions.  A
//! native build maps them one for one onto tokio, the calls the crate made
//! before the seam existed.  A browser build (`wasm_browser`: wasm32 with no
//! operating system) maps them onto the page's event loop, its timers and
//! `performance.now()`, because tokio's runtime, its timer and
//! `std::time::Instant` are not available there.
//!
//! Public so the crates above the endpoint (link-websocket, link-engine,
//! link-web) spawn and keep time on the same runtime as the endpoint.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(wasm_browser))]
pub use std::time::Instant;
#[cfg(wasm_browser)]
pub use web_time::Instant;

#[cfg(not(wasm_browser))]
pub use native::*;
#[cfg(wasm_browser)]
pub use web::*;

/// A [`timeout`] whose deadline passed before its future completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("deadline has elapsed")
    }
}

impl std::error::Error for Elapsed {}

/// Seconds since the Unix epoch by the wall clock, zero if the clock is set
/// before 1970.
pub fn unix_now() -> u64 {
    #[cfg(not(wasm_browser))]
    use std::time::{SystemTime, UNIX_EPOCH};
    #[cfg(wasm_browser)]
    use web_time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(not(wasm_browser))]
mod native {
    use super::*;
    use std::future::Future;

    /// Run `future` in the background.  Nothing waits on it.
    pub fn spawn<F>(future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(future);
    }

    pub fn sleep(duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }

    pub async fn timeout<F: Future>(duration: Duration, future: F) -> Result<F::Output, Elapsed> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(|_| Elapsed)
    }

    /// A periodic tick whose first tick completes at once.  A tick missed
    /// because the task was busy is delayed rather than made up in a burst.
    pub struct Interval(tokio::time::Interval);

    pub fn interval(period: Duration) -> Interval {
        let mut inner = tokio::time::interval(period);
        inner.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Interval(inner)
    }

    impl Interval {
        /// Cancel safe, so it may sit in a `select!` arm.
        pub async fn tick(&mut self) {
            self.0.tick().await;
        }
    }

    /// The runtime quinn drives its endpoint and connections on.
    pub fn quinn_runtime() -> Arc<dyn quinn::Runtime> {
        Arc::new(quinn::TokioRuntime)
    }
}

#[cfg(wasm_browser)]
mod web {
    use super::*;
    use gloo_timers::future::TimeoutFuture;
    use send_wrapper::SendWrapper;
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Run `future` on the page's event loop.  A browser has one thread, so
    /// nothing spawned here needs to be `Send`.
    pub fn spawn<F>(future: F)
    where
        F: Future<Output = ()> + 'static,
    {
        wasm_bindgen_futures::spawn_local(future);
    }

    /// The longest single timer this module sets.  A browser fires a
    /// `setTimeout` above 2^31 - 1 ms (about 24.8 days) at once, and
    /// re-arming it would then spin. A longer wait is a
    /// chain of these, so `Duration::MAX` waits for ever, as in tokio.
    const MAX_TIMER: Duration = Duration::from_secs(20 * 24 * 60 * 60);

    pub async fn sleep(duration: Duration) {
        let mut left = duration;
        while left > MAX_TIMER {
            delay(MAX_TIMER).await;
            left -= MAX_TIMER;
        }
        delay(left).await;
    }

    /// Polls `future` before the deadline each time, as tokio's does.
    pub async fn timeout<F: Future>(duration: Duration, future: F) -> Result<F::Output, Elapsed> {
        tokio::select! {
            biased;
            output = future => Ok(output),
            () = sleep(duration) => Err(Elapsed),
        }
    }

    /// A periodic tick whose first tick completes at once.  A tick missed
    /// because the page was busy is delayed rather than made up in a burst.
    pub struct Interval {
        period: Duration,
        timer: WebTimer,
    }

    pub fn interval(period: Duration) -> Interval {
        assert!(!period.is_zero(), "an interval period must be nonzero");
        Interval {
            period: period.min(MAX_TIMER),
            timer: WebTimer(delay(Duration::ZERO)),
        }
    }

    impl Interval {
        /// The timer belongs to the interval, so cancelling a tick does not
        /// postpone it. A completed tick starts the next period from now.
        pub async fn tick(&mut self) {
            poll_fn(|cx| Pin::new(&mut self.timer.0).poll(cx)).await;
            self.timer.0 = delay(self.period);
        }
    }

    /// The runtime quinn drives its endpoint and connections on.
    pub fn quinn_runtime() -> Arc<dyn quinn::Runtime> {
        Arc::new(WebRuntime)
    }

    /// quinn's runtime on the page's event loop.  Only `new_timer` and
    /// `spawn` are ever called: the endpoint is built over the path socket
    /// with `new_with_abstract_socket`, so quinn never wraps a UDP socket of
    /// its own (and a browser build of quinn has no such hook).
    #[derive(Debug)]
    struct WebRuntime;

    impl quinn::Runtime for WebRuntime {
        fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
            Box::pin(WebTimer(delay(
                deadline.saturating_duration_since(Instant::now()),
            )))
        }

        fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
            wasm_bindgen_futures::spawn_local(future);
        }
    }

    /// One cancellable browser timeout per deadline. Reset drops the old
    /// callback instead of leaving competing callbacks on a shared timer
    /// queue. Quinn requires Send; SendWrapper enforces that this browser
    /// timer is polled and dropped on the event-loop thread that created it.
    fn delay(duration: Duration) -> SendWrapper<TimeoutFuture> {
        // Round up so sub-millisecond deadlines do not repeatedly fire early.
        let millis = duration.min(MAX_TIMER).as_nanos().div_ceil(1_000_000) as u32;
        SendWrapper::new(TimeoutFuture::new(millis))
    }

    #[derive(Debug)]
    struct WebTimer(SendWrapper<TimeoutFuture>);

    impl quinn::AsyncTimer for WebTimer {
        fn reset(self: Pin<&mut Self>, deadline: Instant) {
            self.get_mut().0 = delay(deadline.saturating_duration_since(Instant::now()));
        }

        fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
            Pin::new(&mut self.get_mut().0).poll(cx)
        }
    }
}
