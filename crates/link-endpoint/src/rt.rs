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
    use std::future::Future;
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
    /// wasmtimer would then re-arm it at once and spin; its clock arithmetic
    /// also panics near the top of the `Duration` range.  A longer wait is a
    /// chain of these, so `Duration::MAX` waits for ever, as in tokio.
    const MAX_TIMER: Duration = Duration::from_secs(20 * 24 * 60 * 60);

    pub async fn sleep(duration: Duration) {
        let mut left = duration;
        while left > MAX_TIMER {
            wasmtimer::tokio::sleep(MAX_TIMER).await;
            left -= MAX_TIMER;
        }
        wasmtimer::tokio::sleep(left).await;
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
    pub struct Interval(wasmtimer::tokio::Interval);

    /// A period above `MAX_TIMER` is cut to it; the crate's periods are all
    /// a minute or less.
    pub fn interval(period: Duration) -> Interval {
        let mut inner = wasmtimer::tokio::interval(period.min(MAX_TIMER));
        inner.set_missed_tick_behavior(wasmtimer::tokio::MissedTickBehavior::Delay);
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
            Box::pin(WebTimer(wasmtimer::tokio::sleep_until(timer_instant(
                deadline,
            ))))
        }

        fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
            wasm_bindgen_futures::spawn_local(future);
        }
    }

    /// quinn's clock (`web_time`) and the timer's clock (`wasmtimer`) both
    /// read `performance.now()` but are distinct types, so a deadline is
    /// carried across as the time remaining until it, at most `MAX_TIMER`.
    /// A clamped timer fires early, which quinn tolerates: on every wake it
    /// handles only the timeouts that have actually passed and re-arms.
    fn timer_instant(deadline: Instant) -> wasmtimer::std::Instant {
        let left = deadline.saturating_duration_since(Instant::now());
        wasmtimer::std::Instant::now() + left.min(MAX_TIMER)
    }

    #[derive(Debug)]
    struct WebTimer(wasmtimer::tokio::Sleep);

    impl quinn::AsyncTimer for WebTimer {
        fn reset(self: Pin<&mut Self>, deadline: Instant) {
            Pin::new(&mut self.get_mut().0).reset(timer_instant(deadline));
        }

        fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
            Pin::new(&mut self.get_mut().0).poll(cx)
        }
    }
}
