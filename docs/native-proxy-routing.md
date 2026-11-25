# Native proxy-required relay routing

Native Rust hosts can set `EndpointConfig::proxy_required` to keep Link relay
traffic on an owner-selected SOCKS5 proxy. Use `RelayProxy::Socks5` for a
trusted proxy offering unauthenticated SOCKS5 CONNECT, or `RelayProxy::Tor` for
a Tor SOCKS port with stream isolation enabled. The proxy address is a
literal IP address and port. Use a local proxy or a transport you already trust,
since SOCKS itself exposes the destination to the proxy and its network path.

```rust
use link_endpoint::{Endpoint, EndpointConfig, RelayProxy, RelaySpec};

let mut config = EndpointConfig::new(transport_key);
config.relays = vec![RelaySpec::plain("wss://relay.example/link")];
config.proxy_required = Some(RelayProxy::Tor("127.0.0.1:9050".parse()?));
let endpoint = Endpoint::open(config).await?;
```

Every relay attempt uses the configured proxy, including initial pairing,
ordinary sessions, relay failover and reconnects. Link sends relay DNS names
to the proxy in SOCKS CONNECT, with no local lookup for those names. A failed
or stalled proxy connection follows the ordinary relay retry and timeout
policy. Relay selection is confined to owner-approved destinations.
Proxy-required configuration rejects direct UDP, reflectors, plaintext relay
sockets and unverified relay TLS. QUIC peer authentication runs inside the
relay tunnel.

The same relay hostname is used for WebSocket authority and TLS SNI for a
DNS destination. Ordinary WSS relays can use a WebPKI certificate or an
owner-approved certificate pin. To use an onion service, supply its v3
`wss://` URL and `RelaySpec::pinned` with the SHA-256 of the relay's DER leaf,
obtained through an authenticated channel. The configured SOCKS proxy handles
onion service resolution and address validation.

Tor mode requires username/password authentication with a fresh isolation
label for each relay socket, including reconnects. Use a SOCKS port configured
to honour isolation by SOCKS authentication. Starting a new isolation group
may add circuit setup latency. Link sessions carried by one WebSocket share
that tunnel. Tor and the relay still observe their respective connection
metadata.
[Tor SOCKS specification](https://spec.torproject.org/socks-extensions.html)

The setting is exposed by the native `link-endpoint` Rust API. Browser egress
is governed by browser WebSocket configuration. Android's current Kotlin
binding and any other service connections opened by the host need their own
configuration.
