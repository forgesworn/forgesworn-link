//! ForgeSworn Link in a browser: the paired-route engine of `link-engine`
//! behind a small JavaScript surface, for a page such as a KithMoot client
//! that must reach its box over Link.
//!
//! It mirrors what the Android app uses from link-ffi's `LinkEngine`:
//!
//! ```js
//! const engine = await LinkEngine.start({ transportSeed, relayUrls, routes })
//! const route = await engine.pairRoute({ routeId, serverCard, pairingSecret, expiresAt })
//! await engine.upsertRoute(route)     // also retireRoute, finalizeRoute, removeRoute
//! const reply = await engine.request({ routeId, method, path, authorization, body })
//! const socket = await engine.openSocket(virtualUrl, routeId, { onOpen, onText, onClosed })
//! socket.sendText('...'); socket.disconnect(); socket.path()
//! await engine.stop()
//! ```
//!
//! Every check is link-engine's and link-websocket's, the ones link-ffi
//! runs: route and card verification, the pairing enrolment frames, the
//! request allowlist (cadence, VMLS and witness routes) with its
//! authorization and body rules, the bounded responses, the
//! virtual WebSocket URL, and the text size and queue bounds.  The engine is
//! relay-only, by the endpoint's browser build: its one path is the page's
//! WebSocket to a `wss://` Link relay the browser verifies itself, with no
//! fallback to anything else.
//!
//! What crosses to the page is only what it must hold: the route record it
//! persists (which includes that route's secret) and the application bytes
//! it sends and receives.  There is no getter for the transport seed, the
//! pairing secret or any key, and `stop` removes every route secret from the
//! engine and closes it.
//!
//! On any target other than wasm32-unknown-unknown this library is empty.

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod web;

#[cfg(all(test, target_family = "wasm", target_os = "unknown"))]
mod timer_tests;
