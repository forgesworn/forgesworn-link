//! Loopback WSS relays and an in-process SOCKS fixture. No internet or Tor.

mod harness;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use harness::{MIB, exchange_card, send_and_verify, sink_one_stream};
use link_endpoint::{
    AcceptedSession, Card, Endpoint, EndpointConfig, FailReason, Hint, PathStatus, RelayProxy,
    RelaySpec, RelayStatus, TransportKey,
};
use link_relay::{RelayConfig, RelayHandle, TlsMaterial};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{Request as UpgradeRequest, Response};

const WAIT: Duration = Duration::from_secs(15);
const PAIRING_LIFETIME: Duration = Duration::from_secs(60);

struct Request {
    target: (String, u16),
    isolation: Option<Vec<u8>>,
}

struct Proxy {
    address: SocketAddr,
    requests: mpsc::UnboundedReceiver<Request>,
    task: JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Proxy {
    async fn serve(routes: HashMap<(String, u16), SocketAddr>, method: u8) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (observed, requests) = mpsc::unbounded_channel();
        let routes = Arc::new(routes);
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    entry = listener.accept() => {
                        let (mut client, _) = entry.unwrap();
                        let routes = routes.clone();
                        let observed = observed.clone();
                        clients.spawn(async move {
                            let request = read_connect(&mut client, method).await?;
                            let relay = routes.get(&request.target);
                            observed.send(request).ok();
                            let mut relay = match relay {
                                Some(address) => TcpStream::connect(address).await.ok(),
                                None => None,
                            };
                            if let Some(relay) = &mut relay {
                                client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                                tokio::io::copy_bidirectional(&mut client, relay).await.ok();
                            } else {
                                // Proxy-side lookup/connect failed.
                                client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                            }
                            Ok::<_, std::io::Error>(())
                        });
                    }
                    Some(result) = clients.join_next() => {
                        // Connection resets and cancellation belong to the
                        // tests below. Protocol assertion failures do not.
                        let _ = result.expect("proxy client task");
                    }
                }
            }
        });
        Self {
            address,
            requests,
            task,
        }
    }

    async fn next(&mut self) -> Request {
        timeout(WAIT, self.requests.recv())
            .await
            .expect("proxy saw CONNECT")
            .expect("proxy request channel")
    }
}

async fn read_connect(stream: &mut TcpStream, method: u8) -> std::io::Result<Request> {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 1, method]);
    stream.write_all(&[5, method]).await?;
    let isolation = if method == 2 {
        assert_eq!(stream.read_u8().await?, 1);
        let mut username = vec![0; usize::from(stream.read_u8().await?)];
        stream.read_exact(&mut username).await?;
        assert_eq!(&username, b"<torS0X>0");
        let mut password = vec![0; usize::from(stream.read_u8().await?)];
        stream.read_exact(&mut password).await?;
        assert_eq!(password.len(), 24);
        stream.write_all(&[1, 0]).await?;
        Some(password)
    } else {
        None
    };
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    assert_eq!(&header[..3], &[5, 1, 0]);
    let host = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).to_string()
        }
        3 => {
            let mut bytes = vec![0; usize::from(stream.read_u8().await?)];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).unwrap()
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            Ipv6Addr::from(bytes).to_string()
        }
        other => panic!("unexpected SOCKS5 target type {other}"),
    };
    Ok(Request {
        target: (host, stream.read_u16().await?),
        isolation,
    })
}

async fn relay(host: &str) -> (RelayHandle, RelaySpec) {
    let hosts = vec![host.to_owned()];
    let tls = TlsMaterial::self_signed(&hosts).unwrap();
    let pin = tls.fingerprint();
    let handle = link_relay::start(RelayConfig {
        hosts,
        tls: Some(tls),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let spec = RelaySpec::pinned(handle.url(host), pin);
    (handle, spec)
}

fn config(proxy: RelayProxy, relays: Vec<RelaySpec>) -> EndpointConfig {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = relays;
    config.proxy_required = Some(proxy);
    config.rendezvous_timeout = WAIT;
    config
}

async fn wait_relay(endpoint: &Endpoint, url: &str) {
    let mut status = endpoint.paths().relay().home().watch();
    timeout(
        WAIT,
        status.wait_for(|current| matches!(current, RelayStatus::Up(up) if up == url)),
    )
    .await
    .expect("approved relay became ready")
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_routes_pairing_and_saved_reconnect_via_pinned_relays() {
    let onion = format!("{}.onion", "a".repeat(56));
    let backup = "backup.invalid";
    let (first, first_spec) = relay(&onion).await;
    let (second, second_spec) = relay(backup).await;
    let mut proxy = Proxy::serve(
        HashMap::from([
            ((onion.clone(), first.ws_addr.port()), first.ws_addr),
            ((backup.into(), second.ws_addr.port()), second.ws_addr),
        ]),
        2,
    )
    .await;
    let route = RelayProxy::Tor(proxy.address);
    let relays = vec![first_spec.clone(), second_spec.clone()];
    let alice = Endpoint::open(config(route, relays.clone())).await.unwrap();
    let bob = Endpoint::open(config(route, relays)).await.unwrap();
    let card = exchange_card(&bob);
    let secret = [0x5a; 16];
    let alice_registration = alice
        .register_pairing_secret(secret, PAIRING_LIFETIME)
        .unwrap();
    let bob_registration = bob
        .register_pairing_secret(secret, PAIRING_LIFETIME)
        .unwrap();

    let (dialled, accepted) = timeout(WAIT, async {
        tokio::join!(
            alice.connect_pairing(&card, &alice_registration),
            bob.accept_any()
        )
    })
    .await
    .expect("pairing finished");
    let alice_pairing = dialled.unwrap();
    let AcceptedSession::Pairing(bob_pairing) = accepted.unwrap() else {
        panic!("expected provisional pairing");
    };
    assert_eq!(alice_pairing.peer(), bob.node_id());
    assert_eq!(bob_pairing.peer(), alice.node_id());
    assert_eq!(
        alice_pairing.path().relay.as_deref(),
        Some(first_spec.url.as_str())
    );
    assert!(alice_pairing.path().direct.is_none());
    timeout(WAIT, async {
        let send = async {
            let mut stream = alice_pairing.open_stream().await.unwrap();
            stream.write_all(b"pair").await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(stream.recv.read_to_end(2).await.unwrap(), b"ok");
        };
        let receive = async {
            let mut stream = bob_pairing.accept_stream().await.unwrap();
            assert_eq!(stream.recv.read_to_end(4).await.unwrap(), b"pair");
            stream.write_all(b"ok").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        tokio::join!(send, receive);
    })
    .await
    .expect("provisional request and response finished");

    let alice_secret = alice_pairing.paired_route_secret().unwrap();
    let bob_secret = bob_pairing.paired_route_secret().unwrap();
    assert_eq!(&*alice_secret, &*bob_secret);
    alice
        .rendezvous_book()
        .unwrap()
        .upsert_paired(bob.node_id(), *alice_secret);
    bob.rendezvous_book()
        .unwrap()
        .upsert_paired(alice.node_id(), *bob_secret);
    alice_pairing.close().await;
    drop(alice_registration);
    timeout(WAIT, bob_pairing.closed()).await.unwrap();
    drop(bob_registration);
    first.shutdown();
    tokio::join!(
        wait_relay(&alice, &second_spec.url),
        wait_relay(&bob, &second_spec.url)
    );

    let (dialled, accepted) = timeout(WAIT, async {
        tokio::join!(alice.connect(&card), bob.accept())
    })
    .await
    .expect("saved route reconnect finished");
    let dialled = dialled.unwrap();
    let accepted = accepted.unwrap();
    assert_eq!(dialled.path().status, PathStatus::Relayed);
    assert_eq!(
        dialled.path().relay.as_deref(),
        Some(second_spec.url.as_str())
    );
    assert!(dialled.path().direct.is_none());
    let (outgoing, incoming) = timeout(WAIT, async {
        tokio::join!(
            send_and_verify(&dialled, 0x5eed, MIB),
            sink_one_stream(&accepted, None)
        )
    })
    .await
    .expect("saved route transfer finished");
    outgoing.unwrap();
    assert_eq!(incoming.unwrap(), MIB);

    let mut isolation_groups = HashSet::new();
    let mut hosts = Vec::new();
    for _ in 0..4 {
        let request = proxy.next().await;
        hosts.push(request.target.0);
        assert!(isolation_groups.insert(request.isolation.unwrap()));
    }
    assert_eq!(hosts.iter().filter(|host| **host == onion).count(), 2);
    assert_eq!(hosts.iter().filter(|host| **host == backup).count(), 2);
    tokio::join!(alice.close(), bob.close());
    second.shutdown();
}

#[tokio::test]
async fn proxy_failover_survives_lookup_failure_and_rejects_the_wrong_relay_pin() {
    let unavailable = "unavailable.invalid";
    let wrong_cert = "bad-pin.invalid";
    let backup = "good-pin.invalid";
    let (wrong, wrong_spec) = relay(wrong_cert).await;
    let (good, good_spec) = relay(backup).await;
    let mut proxy = Proxy::serve(
        HashMap::from([
            ((wrong_cert.into(), wrong.ws_addr.port()), wrong.ws_addr),
            ((backup.into(), good.ws_addr.port()), good.ws_addr),
        ]),
        0,
    )
    .await;
    let route = RelayProxy::Socks5(proxy.address);
    let endpoint = Endpoint::open(config(
        route,
        vec![
            RelaySpec::plain(format!("wss://{unavailable}/link")),
            RelaySpec::pinned(&wrong_spec.url, "00".repeat(32)),
            good_spec.clone(),
        ],
    ))
    .await
    .unwrap();
    let _registration = endpoint
        .register_pairing_secret([3; 16], PAIRING_LIFETIME)
        .unwrap();
    wait_relay(&endpoint, &good_spec.url).await;
    for wanted in [unavailable, wrong_cert, backup] {
        let request = proxy.next().await;
        assert_eq!(request.target.0, wanted);
        assert!(request.isolation.is_none());
    }
    endpoint.close().await;
    wrong.shutdown();
    good.shutdown();
}

#[tokio::test]
#[allow(clippy::result_large_err)] // The WebSocket upgrade callback fixes the error type.
async fn proxied_wss_preserves_relay_tls_name_and_websocket_authority() {
    let host = "tls-name.invalid";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let authority = format!("{host}:{}", address.port());
    let url = format!("wss://{authority}/test-link");
    let leaf = TlsMaterial::self_signed(&[host.into()]).unwrap();
    let spec = RelaySpec::pinned(url, leaf.fingerprint());
    let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(leaf.cert_der)],
        PrivatePkcs8KeyDer::from(leaf.key_der).into(),
    )
    .unwrap();
    let received = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(Arc::new(tls_config))
            .accept(socket)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some(host));
        tokio_tungstenite::accept_hdr_async(tls, |request: &UpgradeRequest, response: Response| {
            assert_eq!(request.headers()["host"].to_str().unwrap(), authority);
            assert_eq!(request.uri().path(), "/test-link");
            Ok(response)
        })
        .await
        .unwrap();
    });
    let mut proxy =
        Proxy::serve(HashMap::from([((host.into(), address.port()), address)]), 0).await;
    let endpoint = Endpoint::open(config(RelayProxy::Socks5(proxy.address), vec![spec]))
        .await
        .unwrap();
    let _registration = endpoint
        .register_pairing_secret([3; 16], PAIRING_LIFETIME)
        .unwrap();
    assert_eq!(proxy.next().await.target, (host.into(), address.port()));
    timeout(WAIT, received).await.unwrap().unwrap();
    endpoint.close().await;
}

#[tokio::test]
async fn per_peer_driver_keeps_the_owner_pin_and_refuses_unapproved_destinations() {
    let host_a = "home.invalid";
    let host_b = "peer.invalid";
    let (home, home_spec) = relay(host_a).await;
    let (peer_relay, peer_spec) = relay(host_b).await;
    let mut proxy = Proxy::serve(
        HashMap::from([
            ((host_a.into(), home.ws_addr.port()), home.ws_addr),
            (
                (host_b.into(), peer_relay.ws_addr.port()),
                peer_relay.ws_addr,
            ),
        ]),
        0,
    )
    .await;
    let mut config = config(
        RelayProxy::Socks5(proxy.address),
        vec![home_spec.clone(), peer_spec.clone()],
    );
    let reflector_trap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reflector_address = reflector_trap.local_addr().unwrap();
    config.bind = reflector_address;
    let endpoint = Endpoint::open(config).await.unwrap();
    let registration = endpoint
        .register_pairing_secret([3; 16], PAIRING_LIFETIME)
        .unwrap();
    assert!(endpoint.paths().is_relay_only());
    assert!(
        endpoint
            .card(Duration::from_secs(60), vec![Hint::udp(reflector_address)])
            .udp_candidates()
            .is_empty()
    );
    endpoint.paths().query_reflector(reflector_address);
    wait_relay(&endpoint, &home_spec.url).await;
    assert_eq!(proxy.next().await.target.0, host_a);

    let peer = TransportKey::generate();
    endpoint
        .rendezvous_book()
        .unwrap()
        .upsert_paired(peer.node_id(), [8; 32]);
    let unapproved = "wss://unapproved.invalid/link";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let card = Card::sign(&peer, now, now + 300, 1, vec![Hint::relay(unapproved)]);
    assert!(matches!(
        endpoint.connect(&card).await,
        Err(FailReason::Rendezvous)
    ));
    assert!(matches!(
        endpoint.connect_pairing(&card, &registration).await,
        Err(FailReason::Rendezvous)
    ));

    // Low-level callers cannot supply TLS settings for an approved URL, or add
    // a destination. Without the owner's pin this private leaf fails WebPKI.
    let driver = endpoint.paths().set_peer_relays(
        peer.node_id(),
        &[
            RelaySpec::plain(&peer_spec.url),
            RelaySpec::plain(unapproved),
        ],
    );
    assert_eq!(driver.urls(), std::slice::from_ref(&peer_spec.url));
    assert_eq!(
        timeout(WAIT, driver.wait_up()).await.unwrap(),
        Some(peer_spec.url)
    );
    assert_eq!(proxy.next().await.target.0, host_b);
    assert!(
        timeout(Duration::from_millis(100), proxy.requests.recv())
            .await
            .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(100),
            reflector_trap.recv(&mut [0; 64])
        )
        .await
        .is_err()
    );
    endpoint.close().await;
    home.shutdown();
    peer_relay.shutdown();
}

#[tokio::test]
async fn tor_method_refusal_never_dials_the_relay_directly_and_close_cancels_retry() {
    let relay_trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = relay_trap.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let (retrying, retry) = oneshot::channel();
    let worker = tokio::spawn(async move {
        let (mut first, _) = proxy.accept().await.unwrap();
        let mut hello = [0; 3];
        first.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 1, 2]);
        first.write_all(&[5, 0]).await.unwrap();
        assert_eq!(first.read(&mut hello).await.unwrap(), 0);

        let (mut pending, _) = proxy.accept().await.unwrap();
        pending.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 1, 2]);
        retrying.send(()).unwrap();
        // Deliberately don't finish this negotiation. Closing must cancel it.
        assert_eq!(pending.read(&mut hello).await.unwrap(), 0);
    });
    let mut config = config(
        RelayProxy::Tor(proxy_address),
        vec![RelaySpec::pinned(
            format!("wss://{address}/link"),
            "00".repeat(32),
        )],
    );
    config.rendezvous_timeout = Duration::from_millis(250);
    let endpoint = Endpoint::open(config).await.unwrap();
    let registration = endpoint
        .register_pairing_secret([3; 16], PAIRING_LIFETIME)
        .unwrap();
    timeout(WAIT, retry).await.unwrap().unwrap();
    let peer = TransportKey::generate();
    endpoint
        .rendezvous_book()
        .unwrap()
        .upsert_paired(peer.node_id(), [7; 32]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let card = Card::sign(&peer, now, now + 300, 1, Vec::new());
    let (saved, first) = tokio::join!(
        endpoint.connect(&card),
        endpoint.connect_pairing(&card, &registration)
    );
    assert!(matches!(saved, Err(FailReason::Timeout)));
    assert!(matches!(first, Err(FailReason::Timeout)));
    assert!(
        timeout(Duration::from_millis(100), relay_trap.accept())
            .await
            .is_err()
    );
    timeout(Duration::from_secs(2), endpoint.close())
        .await
        .unwrap();
    timeout(WAIT, worker).await.unwrap().unwrap();
}

#[tokio::test]
async fn proxy_mode_refuses_conflicting_configuration_before_opening_sockets() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9050);
    let base = config(
        RelayProxy::Socks5(address),
        vec![RelaySpec::plain("wss://owner.invalid/link")],
    );
    let configs = [
        EndpointConfig {
            allow_direct: true,
            ..base.clone()
        },
        EndpointConfig {
            reflector: Some(address),
            ..base.clone()
        },
        EndpointConfig {
            allow_unconfigured_relays: true,
            ..base.clone()
        },
        EndpointConfig {
            relays: vec![RelaySpec::plain("ws://owner.invalid/link")],
            ..base.clone()
        },
        EndpointConfig {
            relays: vec![RelaySpec {
                insecure_tls: true,
                ..base.relays[0].clone()
            }],
            ..base.clone()
        },
        EndpointConfig {
            relays: vec![RelaySpec::plain("wss://example.onion/link")],
            ..base.clone()
        },
        EndpointConfig {
            relays: vec![RelaySpec::pinned("wss://owner.invalid/link", "invalid-pin")],
            ..base
        },
    ];
    for config in configs {
        assert!(Endpoint::open(config).await.is_err());
    }
}
