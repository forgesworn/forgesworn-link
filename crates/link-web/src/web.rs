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
    Engine, EngineConfig, EngineError, FileRequestPermit, HTTP_REQUEST_TIMEOUT, JsonRequest,
    PairingBundle, PathInfo, Route,
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
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  authorization: string;
  body: Uint8Array;
}
export interface LinkHttpResponse {
  status: number;
  body: Uint8Array;
  witnessRefused: boolean;
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

// Read internal typed-array extent through captured intrinsic accessors. Caller
// properties (including length/buffer/byteOffset getters) never drive Rust
// allocation. The fresh view is not exposed; its length cannot change between
// js-sys's repeated reads. Shared/resizable backing stores are refused.
// https://tc39.es/ecma262/#sec-get-%typedarray%.prototype.length
#[wasm_bindgen(inline_js = r#"
const NativeUint8Array = Uint8Array;
const apply = Reflect.apply;
const defineProperty = Object.defineProperty;
const typed = Object.getPrototypeOf(NativeUint8Array.prototype);
const getBuffer = Object.getOwnPropertyDescriptor(typed, 'buffer').get;
const getOffset = Object.getOwnPropertyDescriptor(typed, 'byteOffset').get;
const getLength = Object.getOwnPropertyDescriptor(typed, 'length').get;
const getName = Object.getOwnPropertyDescriptor(typed, Symbol.toStringTag).get;
const setBytes = typed.set;
const getBufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const getResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;
export function stableRequestBody(value) {
    if (apply(getName, value, []) !== 'Uint8Array') {
        throw new TypeError('body must be a Uint8Array');
    }
    const buffer = apply(getBuffer, value, []);
    // The ArrayBuffer intrinsic rejects SharedArrayBuffer, including growable
    // storage. The constructor below rejects detached buffers.
    apply(getBufferLength, buffer, []);
    if (getResizable && apply(getResizable, buffer, [])) {
        throw new TypeError('body must use a fixed ArrayBuffer');
    }
    const offset = apply(getOffset, value, []);
    const length = apply(getLength, value, []);
    const view = new NativeUint8Array(buffer, offset, length);
    defineProperty(view, 'length', { value: length });
    return view;
}
export function copyRequestBody(view) {
    const length = apply(getLength, view, []);
    const snapshot = new NativeUint8Array(length);
    apply(setBytes, snapshot, [view]);
    defineProperty(snapshot, 'length', { value: length });
    return snapshot;
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = stableRequestBody)]
    fn stable_request_body(value: &JsValue) -> Result<Uint8Array, JsValue>;
    #[wasm_bindgen(catch, js_name = copyRequestBody)]
    fn copy_request_body(view: &Uint8Array) -> Result<Uint8Array, JsValue>;
}

/// Snapshot metadata, validate the JS byte count and reserve before copying.
/// Later getters cannot redirect the request whose body we accepted.
fn capture_request(
    engine: &Engine,
    request: &JsValue,
) -> Result<(JsonRequest, Option<FileRequestPermit>), JsError> {
    let mut captured = JsonRequest {
        route_id: string(request, "routeId")?,
        method: string(request, "method")?,
        path: string(request, "path")?,
        authorization: string(request, "authorization")?,
        body: Vec::new(),
    };
    let body = stable_request_body(&field(request, "body")?)
        .map_err(|_| invalid("body must be a Uint8Array over a fixed, non-shared buffer"))?;
    let (_, route) = link_engine::validate_http_request_length(&captured, body.length() as usize)
        .map_err(|error| JsError::new(&error.to_string()))?;
    let permit = if route.is_file() {
        Some(
            engine
                .reserve_file_request()
                .map_err(|error| JsError::new(&error.to_string()))?,
        )
    } else {
        None
    };
    // A caller may supply a view into this module's memory. Rust allocation
    // could grow that memory and detach its buffer; take a JS-owned snapshot
    // after validation/reservation and before allocating the Rust copy.
    let snapshot = copy_request_body(&body)
        .map_err(|_| invalid("body could not be copied from its fixed buffer"))?;
    captured.body = snapshot.to_vec();
    Ok((captured, permit))
}

/// The browser Link engine.
#[wasm_bindgen(js_name = LinkEngine)]
pub struct WebEngine {
    /// `None` once stopped; in-flight calls hold their own reference.
    engine: RefCell<Option<Rc<Engine>>>,
    shutdown: RefCell<Option<Promise>>,
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
            shutdown: RefCell::new(None),
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

    /// One bounded, allowlisted request (cadence, VMLS, witness or file) over the
    /// route's pinned session.
    #[wasm_bindgen(unchecked_return_type = "Promise<LinkHttpResponse>")]
    pub fn request(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LinkHttpRequest")] request: JsValue,
    ) -> Promise {
        let engine = match self.engine() {
            Ok(engine) => engine,
            Err(error) => return Promise::reject(&error),
        };
        let (request, permit) = match capture_request(&engine, &request) {
            Ok(request) => request,
            Err(error) => return Promise::reject(&error.into()),
        };
        self.run(|engine| async move {
            let response = engine
                .request_json_reserved(request, HTTP_REQUEST_TIMEOUT, permit)
                .await
                .map_err(engine_error)?;
            let object = Object::new();
            set(&object, "status", &JsValue::from(response.status));
            set(&object, "body", &Uint8Array::from(response.body.as_slice()));
            set(
                &object,
                "witnessRefused",
                &JsValue::from_bool(response.witness_refused),
            );
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
        if let Some(shutdown) = self.shutdown.borrow().as_ref() {
            return shutdown.clone();
        }
        let engine = self.engine.borrow_mut().take();
        let shutdown = future_to_promise(async move {
            if let Some(engine) = engine {
                engine.wipe().await;
            }
            Ok(JsValue::UNDEFINED)
        });
        *self.shutdown.borrow_mut() = Some(shutdown.clone());
        shutdown
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

#[cfg(test)]
mod request_tests {
    use super::*;
    use wasm_bindgen_futures::JsFuture;
    use wasm_bindgen_test::wasm_bindgen_test;

    async fn engine() -> WebEngine {
        WebEngine {
            engine: RefCell::new(Some(Rc::new(
                Engine::start(EngineConfig {
                    transport_seed: vec![7; 32],
                    relay_urls: Vec::new(),
                    allow_direct: false,
                    routes: Vec::new(),
                })
                .await
                .unwrap(),
            ))),
            shutdown: RefCell::new(None),
        }
    }

    fn upload(body: &Uint8Array) -> Object {
        let request = Object::new();
        for (key, value) in [
            ("routeId", "selected"),
            ("method", "PUT"),
            ("path", "/upload"),
            ("authorization", "Nostr YQ=="),
        ] {
            set(&request, key, &JsValue::from_str(value));
        }
        set(&request, "body", body);
        request
    }

    fn message(error: JsValue) -> String {
        Reflect::get(&error, &"message".into())
            .unwrap()
            .as_string()
            .unwrap()
    }

    #[wasm_bindgen_test]
    async fn file_capture_keeps_metadata_and_owned_bytes_after_js_changes() {
        let web = engine().await;
        let engine = web.engine().unwrap();
        let body = Uint8Array::from(b"hello".as_slice());
        let request = upload(&body);
        // A getter is allowed to mutate the original object. Already captured
        // metadata must retain the authorised operation and destination.
        let descriptor = Object::new();
        let getter = Function::new_no_args(
            "this.path = '/elsewhere'; this.routeId = 'other'; return this.savedBody;",
        );
        set(&request, "savedBody", &body);
        set(&descriptor, "get", &getter);
        Object::define_property(&request, &"body".into(), &descriptor);
        let (captured, permit) = capture_request(&engine, request.as_ref()).unwrap();
        body.fill(0, 0, body.length());
        assert_eq!(captured.path, "/upload");
        assert_eq!(captured.route_id, "selected");
        assert_eq!(captured.body, b"hello");
        assert!(engine.reserve_file_request().is_err());
        drop(permit);
        assert!(engine.reserve_file_request().is_ok());
        JsFuture::from(web.stop()).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn file_capture_ignores_overridden_typed_array_extent() {
        let web = engine().await;
        let engine = web.engine().unwrap();
        let backing = Uint8Array::from(b"xhello!".as_slice());
        let body = backing.subarray(1, 6);
        let descriptor = Object::new();
        set(&descriptor, "get", &Function::new_no_args("return 0;"));
        Object::define_property(&body, &"length".into(), &descriptor);
        let forbidden = Object::new();
        set(
            &forbidden,
            "get",
            &Function::new_no_args("throw new Error('caller extent getter was read');"),
        );
        for key in ["buffer", "byteOffset", "byteLength"] {
            Object::define_property(&body, &key.into(), &forbidden);
        }
        // The old boundary rejects this falsely empty body before to_vec,
        // giving a safe regression without executing the unsafe copy path.
        let (captured, permit) = capture_request(&engine, upload(&body).as_ref()).unwrap();
        assert_eq!(captured.body, b"hello");
        drop(permit);
        JsFuture::from(web.stop()).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn owned_body_snapshot_survives_wasm_memory_growth() {
        let memory = wasm_bindgen::memory();
        let buffer = Reflect::get(&memory, &"buffer".into()).unwrap();
        let source = Uint8Array::new_with_byte_offset_and_length(&buffer, 0, 8);
        let view = stable_request_body(source.as_ref()).unwrap();
        let snapshot = copy_request_body(&view).unwrap();
        let expected = snapshot.to_vec();
        let grow = Reflect::get(&memory, &"grow".into())
            .unwrap()
            .dyn_into::<Function>()
            .unwrap();
        grow.call1(&memory, &1.into()).unwrap();
        assert_eq!(source.byte_length(), 0, "original wasm backing detached");
        assert_eq!(snapshot.to_vec(), expected);
    }

    #[wasm_bindgen_test]
    async fn file_capture_refuses_shared_resizable_and_detached_storage() {
        let web = engine().await;
        let engine = web.engine().unwrap();
        for expression in [
            "return new Uint8Array(new SharedArrayBuffer(5));",
            "return new Uint8Array(new ArrayBuffer(5, {maxByteLength: 20}));",
            "const b = new ArrayBuffer(5); const v = new Uint8Array(b); structuredClone(b, {transfer:[b]}); return v;",
        ] {
            let body = Function::new_no_args(expression)
                .call0(&JsValue::UNDEFINED)
                .unwrap();
            let request = upload(&Uint8Array::new_with_length(1));
            set(&request, "body", &body);
            assert!(capture_request(&engine, request.as_ref()).is_err());
            assert!(engine.reserve_file_request().is_ok());
        }
        JsFuture::from(web.stop()).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn file_request_refuses_oversize_and_busy_before_any_route_dial() {
        let web = engine().await;
        let engine = web.engine().unwrap();
        let body = Uint8Array::new_with_length((link_engine::MAX_BLOB_BYTES + 1) as u32);
        let rejected = JsFuture::from(web.request(upload(&body).into()))
            .await
            .unwrap_err();
        assert!(message(rejected).contains("body is too large"));
        let permit = engine.reserve_file_request().unwrap();
        let small = Uint8Array::from(b"hello".as_slice());
        let rejected = JsFuture::from(web.request(upload(&small).into()))
            .await
            .unwrap_err();
        assert!(message(rejected).contains("another file request is still active"));
        drop(permit);
        // With capacity available the same request reaches route lookup, not
        // any external dial: this fixture deliberately has no installed route.
        let rejected = JsFuture::from(web.request(upload(&small).into()))
            .await
            .unwrap_err();
        assert!(message(rejected).contains("route is not installed"));
        assert!(engine.reserve_file_request().is_ok());
        JsFuture::from(web.stop()).await.unwrap();
        let rejected = JsFuture::from(web.request(upload(&small).into()))
            .await
            .unwrap_err();
        assert!(message(rejected).contains("stopped"));
    }
}
