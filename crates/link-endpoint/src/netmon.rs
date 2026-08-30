//! A small interface monitor, spec 4.2: it polls the set of interface
//! addresses and bumps a generation counter when the set changes, so a
//! session can re-query the reflector and re-announce its candidates.
//!
//! Polling is the portable baseline, and five seconds is what a platform
//! notification would also amount to in practice; an application that has a
//! connectivity callback calls `Session::reannounce` itself and may set the
//! poll to zero to switch this off.

use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::watch;

/// The interface monitor.  It has no state of its own: `spawn` returns the
/// generation counter and the task behind it lives as long as a receiver.
pub struct NetMonitor;

impl NetMonitor {
    /// Poll `snapshot` every `poll` and advance the generation whenever the
    /// address set differs from the last one seen.  Order and duplicates are
    /// not a change.  A zero `poll` runs no polling task and the generation
    /// stays at zero for ever.
    pub fn spawn(
        poll: Duration,
        snapshot: impl Fn() -> Vec<IpAddr> + Send + 'static,
    ) -> watch::Receiver<u64> {
        let (tx, rx) = watch::channel(0u64);
        if poll.is_zero() {
            // Keep the channel open so a subscriber sees "never changes"
            // rather than "sender gone"; the task ends with the last receiver.
            tokio::spawn(async move { tx.closed().await });
            return rx;
        }
        tokio::spawn(async move {
            let mut last = normalised(snapshot());
            let mut tick = tokio::time::interval(poll);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick of an interval completes at once.
            tick.tick().await;
            loop {
                tick.tick().await;
                if tx.is_closed() {
                    break;
                }
                let now = normalised(snapshot());
                if now != last {
                    last = now;
                    tx.send_modify(|generation| *generation += 1);
                }
            }
        });
        rx
    }
}

fn normalised(mut set: Vec<IpAddr>) -> Vec<IpAddr> {
    set.sort();
    set.dedup();
    set
}

/// Every interface address on the host, the snapshot an endpoint monitors.
pub fn interface_snapshot() -> Vec<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|list| list.into_iter().map(|interface| interface.ip()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// The generation advances once for a change in the address set and not
    /// at all for a poll that sees the same set.
    #[tokio::test]
    async fn generation_advances_only_when_the_address_set_changes() {
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let mut generation = NetMonitor::spawn(Duration::from_millis(20), move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            // The same set for the first two polls, then one more address,
            // then unchanged for good.
            let mut set = vec![IpAddr::from([10, 0, 0, 1])];
            if n >= 2 {
                set.push(IpAddr::from([192, 168, 1, 5]));
            }
            set
        });
        assert_eq!(*generation.borrow(), 0, "nothing has changed yet");
        tokio::time::timeout(Duration::from_secs(2), generation.changed())
            .await
            .expect("a change within two seconds")
            .expect("the monitor is alive");
        assert_eq!(*generation.borrow_and_update(), 1);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            *generation.borrow(),
            1,
            "an unchanged set never advances the generation"
        );
        assert!(
            polls.load(Ordering::SeqCst) >= 5,
            "the monitor kept polling"
        );
    }

    /// A zero poll interval means no polling: the snapshot is never taken
    /// and the generation never moves, but a subscriber still sees an open
    /// channel rather than a closed one.
    #[tokio::test]
    async fn a_zero_interval_disables_the_monitor() {
        let mut generation =
            NetMonitor::spawn(Duration::ZERO, || panic!("a disabled monitor never polls"));
        assert_eq!(*generation.borrow(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), generation.changed())
                .await
                .is_err(),
            "no change is ever announced"
        );
    }

    /// The order the OS lists addresses in is not a change.
    #[tokio::test]
    async fn address_order_is_not_a_change() {
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let mut generation = NetMonitor::spawn(Duration::from_millis(10), move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let a = IpAddr::from([10, 0, 0, 1]);
            let b = IpAddr::from([10, 0, 0, 2]);
            if n.is_multiple_of(2) {
                vec![a, b]
            } else {
                vec![b, a]
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(120), generation.changed())
                .await
                .is_err(),
            "reordering never advances the generation"
        );
    }
}
