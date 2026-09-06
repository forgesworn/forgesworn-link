use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn stopping_readiness_before_its_fin_cannot_admit_a_session() {
    let phone = LanEndpoint::open(TransportKey::generate(), LanBinding::default()).unwrap();
    let window = LanPairingListener::open(
        TransportKey::generate(),
        LanBinding::default(),
        Duration::from_secs(30),
    )
    .unwrap();
    let mut config = tls::client(phone.core.identity.clone(), window.node_id(), true).unwrap();
    let mut transport = quinn::TransportConfig::default();
    // One byte of credit lets us stop readiness before the remaining bytes or
    // FIN can arrive. STOP_SENDING is not acknowledgement of the ready message.
    transport
        .max_concurrent_uni_streams(1_u32.into())
        .stream_receive_window(1_u32.into());
    config.transport_config(Arc::new(transport));
    let connection = phone
        .core
        .quic
        .connect_with(config, window.local_addr().unwrap(), "lan.invalid")
        .unwrap()
        .await
        .unwrap();
    let mut ready = connection.accept_uni().await.unwrap();
    ready.stop(7_u32.into()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), connection.closed())
        .await
        .expect("stopped readiness must close the connection");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), window.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn server_pairing_ceiling_holds_against_a_raw_client_that_keeps_transferring() {
    let phone = LanEndpoint::open(TransportKey::generate(), LanBinding::default()).unwrap();
    let window = Arc::new(
        LanPairingListener::open(
            TransportKey::generate(),
            LanBinding::default(),
            Duration::from_secs(120),
        )
        .unwrap(),
    );
    // Bypass the cooperative client session and its deadline. Only the server
    // can enforce the sixty-second cap in this hostile-client test.
    let connection = phone
        .core
        .quic
        .connect_with(
            tls::client(phone.core.identity.clone(), window.node_id(), true).unwrap(),
            window.local_addr().unwrap(),
            "lan.invalid",
        )
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        connection
            .accept_uni()
            .await
            .unwrap()
            .read_to_end(READY.len())
            .await
            .unwrap(),
        READY
    );
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let accepted = window.accept().await.unwrap();
    let start = Instant::now();
    let serving = tokio::spawn(async move {
        let mut stream = accepted.stream().await.unwrap();
        let mut byte = [0];
        let mut received = 0;
        loop {
            if stream.read_exact(&mut byte).await.is_err() {
                break;
            }
            if stream.write_all(&byte).await.is_err() {
                break;
            }
            received += 1;
        }
        assert!(!accepted.is_live());
        received
    });
    let transferred = tokio::time::timeout(MAX_PAIRING_SESSION + Duration::from_secs(3), async {
        let mut count = 0;
        loop {
            if send.write_all(b"x").await.is_err() {
                break;
            }
            let mut byte = [0];
            if recv.read_exact(&mut byte).await.is_err() {
                break;
            }
            count += 1;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        count
    })
    .await
    .expect("server must close a busy provisional connection by its absolute deadline");
    assert!(
        transferred >= 10,
        "the connection must stay busy, not merely time out idle"
    );
    assert!(start.elapsed() >= Duration::from_secs(58));
    assert!(serving.await.unwrap() >= 10);
}

#[test]
fn local_subnet_policy_rejects_broadcast_network_other_subnet_and_bad_ipv6_scope() {
    let policy = AddressPolicy {
        bind: "192.168.7.10:4000".parse().unwrap(),
        interface: Some((
            "synthetic".into(),
            "255.255.255.0".parse().unwrap(),
            Some(1),
        )),
    };
    assert!(policy.permits("192.168.7.20:5000".parse().unwrap()));
    for address in [
        "192.168.7.255:5000",
        "192.168.7.0:5000",
        "192.168.8.20:5000",
        "192.168.7.20:0",
        "[::ffff:192.168.7.20]:5000",
    ] {
        assert!(!policy.permits(address.parse().unwrap()));
    }
    let policy = AddressPolicy {
        bind: "[fe80::10%3]:4000".parse().unwrap(),
        interface: Some((
            "synthetic".into(),
            "ffff:ffff:ffff:ffff::".parse().unwrap(),
            Some(3),
        )),
    };
    assert!(policy.permits("[fe80::20%3]:5000".parse().unwrap()));
    assert!(!policy.permits("[fe80::20%4]:5000".parse().unwrap()));
    assert!(!policy.permits("[fe80::20]:5000".parse().unwrap()));
}

#[tokio::test]
async fn revocation_before_accept_cannot_hand_a_stale_handshake_to_the_product() {
    let a = LanEndpoint::open(TransportKey::generate(), LanBinding::default()).unwrap();
    let b = LanEndpoint::open(TransportKey::generate(), LanBinding::default()).unwrap();
    let card = a.card(Duration::from_secs(30), 1).unwrap();
    let admission = b.admit_peer(a.node_id(), card.as_bytes(), None).unwrap();
    let mut connecting = a
        .core
        .quic
        .connect_with(
            tls::client(a.core.identity.clone(), b.node_id(), false).unwrap(),
            b.local_addr().unwrap(),
            "lan.invalid",
        )
        .unwrap();
    connecting.handshake_data().await.unwrap();
    drop(admission);
    if let Ok(connection) = connecting.await {
        connection.close(0_u32.into(), b"test complete");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), b.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn socket_filter_refuses_an_unselected_destination_even_below_the_endpoint_api() {
    let policy = AddressPolicy::new(LanBinding::default()).unwrap();
    let socket = std::net::UdpSocket::bind(policy.bind).unwrap();
    socket.set_nonblocking(true).unwrap();
    let counters = Arc::new(Counters::default());
    let active = Arc::new(AtomicBool::new(true));
    let socket = LocalSocket {
        inner: quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(),
        policy,
        active: active.clone(),
        counters: counters.clone(),
    };
    use quinn::AsyncUdpSocket;
    let packet = quinn::udp::Transmit {
        destination: "192.0.2.1:443".parse().unwrap(),
        ecn: None,
        contents: b"synthetic",
        segment_size: None,
        src_ip: None,
    };
    assert_eq!(
        socket.try_send(&packet).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(counters.sent.load(Ordering::Relaxed), 0);
    assert_eq!(counters.refused.load(Ordering::Relaxed), 1);
    active.store(false, Ordering::Release);
    let packet = quinn::udp::Transmit {
        destination: "127.0.0.1:443".parse().unwrap(),
        ..packet
    };
    assert_eq!(
        socket.try_send(&packet).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
