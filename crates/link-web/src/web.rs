//! The wasm-bindgen surface.  It converts JavaScript values to link-engine's
//! types and back and runs each call on the page's event loop; every
//! decision is link-engine's.

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use link_endpoint::Session;
use link_engine::{
    Engine, EngineConfig, EngineError, HTTP_REQUEST_TIMEOUT, JsonRequest, PairingBundle, PathInfo,
    Route,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, spawn_local};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
/** One paired route, exactly as the page must persist it. */
export interface LinkRoute {
  routeId: string;
  card: Uint8Array;
  pairedRouteSecret: Uint8Array;
  /** A u64 carried exactly; a safe-integer number is also accepted. */
  cardSerial: bigint;
  /** Unix seconds, a u64 carried exactly; a safe-integer number is also accepted. */
  cardVerifiedAt: bigint;
}
export interface LinkConfig {
  /** 32 bytes, supplied by the host from its own encrypted storage. */
  transportSeed: Uint8Array;
  /** wss:// relays only; a browser cannot pin or skip certificate checks. */
  relayUrls: string[];
  routes: LinkRoute[];
}
export interface LinkPairingBundle {
  routeId: string;
  serverCard: Uint8Array;
  /** The QR's 16 raw capability bytes; never retained. */
  pairingSecret: Uint8Array;
  /** Absolute Unix-second deadline. */
  expiresAt: number;
}
export interface LinkPath {
  status: string;
  relay: string | null;
  direct: string | null;
  cause: string;
}
export interface LinkHttpRequest {
  routeId: string;
  method: "POST" | "PUT";
  path: string;
  authorization: string;
  body: Uint8Array;
}
export interface LinkHttpResponse {
  status: number;
  body: Uint8Array;
  path: LinkPath;
}
export interface LinkSocketListener {
  onOpen?: () => void;
  onText?: (text: string) => void;
  onClosed?: (reason: string) => void;
}
"#;

/// The largest integer a JavaScript number carries exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn engine_error(error: EngineError) -> JsValue {
    JsError::new(&error.to_string()).into()
}

fn invalid(message: &str) -> JsError {
    JsError::new(&format!("configuration: {message}"))
}

fn field(object: &JsValue, name: &str) -> Result<JsValue, JsError> {
    if !object.is_object() {
        return Err(invalid(&format!("expected an object holding {name}")));
    }
    Reflect::get(object, &JsValue::from_str(name))
        .map_err(|_| invalid(&format!("{name} could not be read")))
}

fn string(object: &JsValue, name: &str) -> Result<String, JsError> {
    field(object, name)?
        .as_string()
        .ok_or_else(|| invalid(&format!("{name} must be a string")))
}

fn bytes(object: &JsValue, name: &str) -> Result<Vec<u8>, JsError> {
    field(object, name)?
        .dyn_into::<Uint8Array>()
        .map(|array| array.to_vec())
        .map_err(|_| invalid(&format!("{name} must be a Uint8Array")))
}

fn integer(object: &JsValue, name: &str) -> Result<u64, JsError> {
    field(object, name)?
        .as_f64()
        .filter(|value| {
            value.is_finite()
                && value.fract() == 0.0
                && (0.0..=MAX_SAFE_INTEGER as f64).contains(value)
        })
        .map(|value| value as u64)
        .ok_or_else(|| invalid(&format!("{name} must be a non-negative safe integer")))
}

fn list(object: &JsValue, name: &str) -> Result<Array, JsError> {
    let value = field(object, name)?;
    if !Array::is_array(&value) {
        return Err(invalid(&format!("{name} must be an array")));
    }
    Ok(Array::from(&value))
}

/// A u64 from a BigInt, or from a number that holds it exactly.
fn wide(object: &JsValue, name: &str) -> Result<u64, JsError> {
    let value = field(object, name)?;
    if value.is_bigint() {
        return u64::try_from(value).map_err(|_| invalid(&format!("{name} must be a u64 BigInt")));
    }
    integer(object, name)
}

fn set(object: &Object, name: &str, value: &JsValue) {
    // Setting a plain data property on a fresh object cannot fail.
    let _ = Reflect::set(object, &JsValue::from_str(name), value);
}

/// Every other field is read before the secret is copied out of the page,
/// so a malformed record never leaves a stray copy; once copied it is in a
/// `Route`, which zeroises it on drop.
fn route_in(value: &JsValue) -> Result<Route, JsError> {
    let route_id = string(value, "routeId")?;
    let card = bytes(value, "card")?;
    let card_serial = wide(value, "cardSerial")?;
    let card_verified_at = wide(value, "cardVerifiedAt")?;
    Ok(Route {
        route_id,
        card,
        paired_route_secret: bytes(value, "pairedRouteSecret")?,
        card_serial,
        card_verified_at,
    })
}

/// Infallible, so a route the server has enrolled always reaches the page:
/// its u64 fields go across as BigInt, which holds every value exactly.
fn route_out(route: &Route) -> JsValue {
    let object = Object::new();
    set(&object, "routeId", &JsValue::from_str(&route.route_id));
    set(&object, "card", &Uint8Array::from(route.card.as_slice()));
    set(
        &object,
        "pairedRouteSecret",
        &Uint8Array::from(route.paired_route_secret.as_slice()),
    );
    set(&object, "cardSerial", &JsValue::from(route.card_serial));
    set(
        &object,
        "cardVerifiedAt",
        &JsValue::from(route.card_verified_at),
    );
    object.into()
}

fn path_out(path: PathInfo) -> JsValue {
    let object = Object::new();
    set(&object, "status", &JsValue::from_str(&path.status));
    let optional = |value: Option<String>| value.map_or(JsValue::NULL, |v| JsValue::from_str(&v));
    set(&object, "relay", &optional(path.relay));
    set(&object, "direct", &optional(path.direct));
    set(&object, "cause", &JsValue::from_str(&path.cause));
    object.into()
}

fn callback(listener: &JsValue, name: &str) -> Result<Option<Function>, JsError> {
    let value = field(listener, name)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    value
        .dyn_into::<Function>()
        .map(Some)
        .map_err(|_| invalid(&format!("listener {name} must be a function")))
}

/// The browser Link engine.
#[wasm_bindgen(js_name = LinkEngine)]
pub struct WebEngine {
    /// `None` once stopped; in-flight calls hold their own reference.
    engine: RefCell<Option<Rc<Engine>>>,
}

#[wasm_bindgen(js_class = LinkEngine)]
impl WebEngine {
    /// Open the endpoint on the host's transport seed and install the
    /// persisted routes.  Relay-only; every relay must be `wss://`.
    pub async fn start(
        #[wasm_bindgen(unchecked_param_type = "LinkConfig")] config: JsValue,
    ) -> Result<WebEngine, JsError> {
        let routes = list(&config, "routes")?
            .iter()
            .map(|route| route_in(&route))
            .collect::<Result<Vec<_>, _>>()?;
        let relay_urls = list(&config, "relayUrls")?
            .iter()
            .map(|url| {
                url.as_string()
                    .ok_or_else(|| invalid("relayUrls must hold strings"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let config = EngineConfig {
            transport_seed: bytes(&config, "transportSeed")?,
            relay_urls,
            allow_direct: false,
            routes,
        };
        let engine = Engine::start(config)
            .await
            .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(WebEngine {
            engine: RefCell::new(Some(Rc::new(engine))),
        })
    }

    fn engine(&self) -> Result<Rc<Engine>, JsValue> {
        self.engine
            .borrow()
            .clone()
            .ok_or_else(|| engine_error(EngineError::Stopped))
    }

    fn run<F>(&self, call: impl FnOnce(Rc<Engine>) -> F) -> Promise
    where
        F: Future<Output = Result<JsValue, JsValue>> + 'static,
    {
        match self.engine() {
            Ok(engine) => future_to_promise(call(engine)),
            Err(error) => Promise::reject(&error),
        }
    }

    /// Enrol a route from a scanned pairing QR and return the exact record
    /// the page must persist.  The route is also installed at once.
    #[wasm_bindgen(js_name = pairRoute, unchecked_return_type = "Promise<LinkRoute>")]
    pub fn pair_route(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LinkPairingBundle")] bundle: JsValue,
    ) -> Promise {
        // The capability is copied last, straight into a bundle that
        // zeroises it on drop.
        let bundle = match (|| {
            let route_id = string(&bundle, "routeId")?;
            let server_card = bytes(&bundle, "serverCard")?;
            let expires_at = integer(&bundle, "expiresAt")?;
            Ok::<_, JsError>(PairingBundle {
                route_id,
                server_card,
                pairing_secret: bytes(&bundle, "pairingSecret")?,
                expires_at,
            })
        })() {
            Ok(bundle) => bundle,
            Err(error) => return Promise::reject(&error.into()),
        };
        self.run(|engine| async move {
            let route = engine.pair_route(bundle).await.map_err(engine_error)?;
            Ok(route_out(&route))
        })
    }

    /// Install a newer record of a route (its card serial must increase).
    #[wasm_bindgen(js_name = upsertRoute, unchecked_return_type = "Promise<void>")]
    pub fn upsert_route(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LinkRoute")] route: JsValue,
    ) -> Promise {
        let route = match route_in(&route) {
            Ok(route) => route,
            Err(error) => return Promise::reject(&error.into()),
        };
        self.run(|engine| async move {
            engine.upsert_route(route).await.map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Ask the paired server to retire the route.  Local credentials stay.
    #[wasm_bindgen(js_name = retireRoute, unchecked_return_type = "Promise<void>")]
    pub fn retire_route(&self, #[wasm_bindgen(js_name = routeId)] route_id: String) -> Promise {
        self.run(|engine| async move {
            engine.retire_route(&route_id).await.map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Remove the paired transport at the server after logical retirement.
    #[wasm_bindgen(js_name = finalizeRoute, unchecked_return_type = "Promise<void>")]
    pub fn finalize_route(&self, #[wasm_bindgen(js_name = routeId)] route_id: String) -> Promise {
        self.run(|engine| async move {
            engine
                .finalize_route(&route_id)
                .await
                .map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Forget a route locally and close its session.
    #[wasm_bindgen(js_name = removeRoute, unchecked_return_type = "Promise<void>")]
    pub fn remove_route(&self, #[wasm_bindgen(js_name = routeId)] route_id: String) -> Promise {
        self.run(|engine| async move {
            engine.remove_route(&route_id).await.map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// One bounded cadence JSON request over the route's pinned session.
    #[wasm_bindgen(unchecked_return_type = "Promise<LinkHttpResponse>")]
    pub fn request(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LinkHttpRequest")] request: JsValue,
    ) -> Promise {
        let request = match (|| {
            Ok::<_, JsError>(JsonRequest {
                route_id: string(&request, "routeId")?,
                method: string(&request, "method")?,
                path: string(&request, "path")?,
                authorization: string(&request, "authorization")?,
                body: bytes(&request, "body")?,
            })
        })() {
            Ok(request) => request,
            Err(error) => return Promise::reject(&error.into()),
        };
        self.run(|engine| async move {
            let response = engine
                .request_json(request, HTTP_REQUEST_TIMEOUT)
                .await
                .map_err(engine_error)?;
            let object = Object::new();
            set(&object, "status", &JsValue::from(response.status));
            set(&object, "body", &Uint8Array::from(response.body.as_slice()));
            set(&object, "path", &path_out(response.path));
            Ok(object.into())
        })
    }

    /// Open the route's event WebSocket: text only, bounded as link-websocket
    /// bounds it, over a Link stream to the route's pinned peer.
    #[wasm_bindgen(js_name = openSocket, unchecked_return_type = "Promise<LinkSocket>")]
    pub fn open_socket(
        &self,
        #[wasm_bindgen(js_name = virtualUrl)] virtual_url: String,
        #[wasm_bindgen(js_name = routeId)] route_id: String,
        #[wasm_bindgen(unchecked_param_type = "LinkSocketListener")] listener: JsValue,
    ) -> Promise {
        let callbacks = (|| {
            Ok::<_, JsError>((
                callback(&listener, "onOpen")?,
                callback(&listener, "onText")?,
                callback(&listener, "onClosed")?,
            ))
        })();
        let (on_open, on_text, on_closed) = match callbacks {
            Ok(callbacks) => callbacks,
            Err(error) => return Promise::reject(&error.into()),
        };
        self.run(|engine| async move {
            let (socket, mut incoming, session) = engine
                .open_socket(&virtual_url, &route_id)
                .await
                .map_err(engine_error)?;
            if let Some(on_open) = &on_open {
                let _ = on_open.call0(&JsValue::NULL);
            }
            spawn_local(async move {
                while let Some(message) = incoming.recv().await {
                    match message {
                        link_websocket::IncomingMessage::Text(text) => {
                            if let Some(on_text) = &on_text {
                                let _ = on_text.call1(&JsValue::NULL, &JsValue::from_str(&text));
                            }
                        }
                        link_websocket::IncomingMessage::Closed(reason) => {
                            if let Some(on_closed) = &on_closed {
                                let _ =
                                    on_closed.call1(&JsValue::NULL, &JsValue::from_str(&reason));
                            }
                            return;
                        }
                    }
                }
            });
            Ok(WebSocketHandle { socket, session }.into())
        })
    }

    /// Stop the engine: refuse every later call, close its sessions, remove
    /// every route secret from it and close the endpoint.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn stop(&self) -> Promise {
        let engine = self.engine.borrow_mut().take();
        future_to_promise(async move {
            if let Some(engine) = engine {
                engine.wipe().await;
            }
            Ok(JsValue::UNDEFINED)
        })
    }
}

/// A text WebSocket over a Link stream.
#[wasm_bindgen(js_name = LinkSocket)]
pub struct WebSocketHandle {
    socket: link_websocket::Socket,
    session: Arc<Session>,
}

#[wasm_bindgen(js_class = LinkSocket)]
impl WebSocketHandle {
    /// Queue one text message; refused above the size bound or when the
    /// outbound queue is full (which also closes the socket).
    #[wasm_bindgen(js_name = sendText)]
    pub fn send_text(&self, text: String) -> Result<(), JsError> {
        self.socket
            .send_text(text)
            .map_err(|error| JsError::new(&format!("socket: {error}")))
    }

    /// Start a normal close; `onClosed` reports the end.
    pub fn disconnect(&self) -> Result<(), JsError> {
        self.socket
            .close()
            .map_err(|error| JsError::new(&format!("socket: {error}")))
    }

    #[wasm_bindgen(unchecked_return_type = "LinkPath")]
    pub fn path(&self) -> JsValue {
        path_out(link_engine::path(&self.session))
    }
}
