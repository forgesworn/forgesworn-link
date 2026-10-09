//! These exercise the actual WASM runtime, with the test runner's independent
//! JavaScript watchdog bounding a stalled timer.
use futures_util::FutureExt;
use link_endpoint::rt;
use std::future::poll_fn;
use std::time::Duration;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
async fn reset_and_cancel_churn_does_not_starve_a_quic_deadline() {
    let runtime = rt::quinn_runtime();
    let mut timer = runtime.new_timer(rt::Instant::now() + Duration::from_secs(60));
    for _ in 0..128 {
        timer
            .as_mut()
            .reset(rt::Instant::now() + Duration::from_secs(60));
        // Give the event loop a turn: old schedulers left competing long
        // callbacks behind on every reset, eventually suppressing deadlines.
        gloo_yield().await;
    }
    timer
        .as_mut()
        .reset(rt::Instant::now() + Duration::from_millis(10));
    let started = rt::Instant::now();
    poll_fn(|cx| timer.as_mut().poll(cx)).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    // An already fired timer must be reusable.
    timer
        .as_mut()
        .reset(rt::Instant::now() + Duration::from_millis(10));
    poll_fn(|cx| timer.as_mut().poll(cx)).await;
}

async fn gloo_yield() {
    // Use a JS Promise rather than the timer under test to drive the churn.
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let global = js_sys::global();
        let timeout = js_sys::Reflect::get(&global, &"setTimeout".into()).unwrap();
        let timeout: js_sys::Function = timeout.into();
        timeout.call2(&global, &resolve, &1.into()).unwrap();
    });
    wasm_bindgen_futures::JsFuture::from(promise).await.unwrap();
}

#[wasm_bindgen_test]
async fn simultaneous_deadlines_and_cancelled_ticks_keep_progressing() {
    let runtime = rt::quinn_runtime();
    let mut timers: Vec<_> = (0..64)
        .map(|_| runtime.new_timer(rt::Instant::now() + Duration::from_millis(20)))
        .collect();
    let started = rt::Instant::now();
    futures_util::future::join_all(
        timers
            .iter_mut()
            .map(|timer| poll_fn(|cx| timer.as_mut().poll(cx))),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(2));
    let mut interval = rt::interval(Duration::from_millis(200));
    interval.tick().await;
    for _ in 0..100 {
        assert!(interval.tick().now_or_never().is_none());
    }
    assert!(
        rt::timeout(Duration::from_millis(300), interval.tick())
            .await
            .is_ok()
    );
    // A huge duration must stay pending, without an overflowing JS timeout.
    assert!(
        rt::timeout(Duration::from_millis(10), rt::sleep(Duration::MAX))
            .await
            .is_err()
    );
}
