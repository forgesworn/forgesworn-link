# Browser shutdown completion

The browser endpoint retains its QUIC drain (`wait_idle`) and now also waits
for every relay driver to exit and every browser WebSocket opened by those
drivers to reach `CLOSED`. This includes cancelled handshakes and earlier
sockets still closing after a reconnect. Closing the pool prevents new drivers
and refuses new outbound frames. Native sockets terminate when their owning
driver future is dropped.

Concurrent native engine stops wait for the same serialised teardown; cancelling
one stop does not make the stop flag stand in for completion. The browser
wrapper returns the same completion Promise to every `stop()` caller. Route
secrets are removed by `wipe` only after the transport barrier finishes. There
is no timeout that turns an incomplete close into success.

## Timer stall

A real-Bothy browser journey repeatedly created, signed with and closed witness
connections. Instrumentation on the old runtime recorded a 109 ms QUIC deadline
which remained pending for minutes. Reads and advances had already completed.
The pinned wasmtimer 0.4.3 scheduler leaves overlapping callbacks after resets
and stops scheduling the next deadline while its shared timer reference count
exceeds 20 (`src/timer/global.rs`).

Browser deadlines now use one cancellable Gloo timeout per wait. Reset drops
the previous timeout and its callback. SendWrapper enforces the existing
single-event-loop runtime requirement imposed by Quinn's Send timer interface.
Long waits remain chunked below the browser's signed 32-bit timeout limit;
sub-millisecond waits round up. Cancelled interval ticks retain their deadline.
No native Tokio timer, wire format, route validation or privacy mode changes.

## Regression commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
WASI_SDK=/path/to/wasi-sdk-34.0 scripts/test-link-web.sh
WASI_SDK=/path/to/wasi-sdk-34.0 cargo test -p link-web --test browser_e2e
```

The WASM tests have a CI wall-clock bound and cover reset
churn, concurrent deadlines, interval cancellation, long waits, cancelled socket
opens and a replacement socket closing before its predecessor. The native
engine regression cancels shutdown and retries it before the first barrier can
complete. The WebPKI loopback test checks shared browser stop-Promise identity.
The live KithMoot witness journey checks all observed sockets are closed after
each returned operation across Chromium, Firefox and WebKit.

The owner-authorised independent reviewer found no security or lifetime blocker
in the implementation. That source review is separate from automated and live
lab results; it is not a human cryptographic audit or production MLS approval.
The result does not establish physical-device behaviour or MLS room acceptance.


## Recorded local results, 9 October 2026

- Formatting, workspace clippy and the native workspace suite passed (138
  passing results; one explicitly ignored public-relay test).
- Three WASM regressions passed. The reset-churn regression, copied to the
  unmodified runtime at `8f7bebd`, failed its two-second elapsed assertion:
  it completed only after the old 60-second deadline. The repaired test
  suite completed in under a second.
- The Node WebPKI pairing/request/socket/restart test passed, including shared
  stop-Promise identity and the five-second shutdown bound.
- Six extended real-Bothy journeys passed across Chromium, Firefox and WebKit
  in 2.9 minutes; all observed sockets were closed at each returned operation.
- The owner-authorised independent reviewer inspected `2fa7f23`, found no
  blocker, and separately passed formatting and diff checks. Heavy test results
  above were run by the implementation agent, not independently repeated.

These are disposable loopback lab results, not physical-device acceptance.
