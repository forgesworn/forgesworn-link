#![cfg(feature = "experimental-lan")]

use link_core::card::{Card, Hint};
use link_endpoint::{TransportKey, lan::*};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn endpoint() -> LanEndpoint {
    LanEndpoint::open(TransportKey::generate(), LanBinding::default()).unwrap()
}
fn card(endpoint: &LanEndpoint, serial: u64) -> Card {
    endpoint.card(Duration::from_secs(120), serial).unwrap()
}
fn admit(a: &LanEndpoint, b: &LanEndpoint) -> LanAdmission {
    let card = card(b, 1);
    let checkpoint = verify_peer_card(b.node_id(), card.as_bytes(), None).unwrap();
    a.admit_peer(b.node_id(), card.as_bytes(), Some(&checkpoint))
        .unwrap()
}

#[tokio::test]
async fn fresh_pinned_endpoints_stream_exact_bytes_without_a_relay_or_prior_contact() {
    let a = endpoint();
    let b = Arc::new(endpoint());
    let to_b = admit(&a, &b);
    let _to_a = admit(&b, &a);
    let server = b.clone();
    let serving = tokio::spawn(async move {
        let session = server.accept().await.unwrap();
        let mut stream = session.accept_stream().await.unwrap();
        let mut buffer = [0; 64 * 1024];
        let mut hash = Sha256::new();
        let mut size = 0;
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
            size += read;
        }
        stream.write_all(&hash.finalize()).await.unwrap();
        stream.finish().await.unwrap();
        size
    });
    let session = a.connect(&to_b, b.local_addr().unwrap()).await.unwrap();
    assert_eq!(session.peer(), b.node_id());
    let mut stream = session.open_stream().await.unwrap();
    let bytes = (0..5 * 1024 * 1024 + 31)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    stream.write_all(&bytes).await.unwrap();
    stream.finish().await.unwrap();
    let mut returned = Vec::new();
    stream.read_to_end(&mut returned).await.unwrap();
    assert_eq!(returned, Sha256::digest(&bytes).as_slice());
    assert_eq!(serving.await.unwrap(), bytes.len());
    assert!(a.traffic().sent_datagrams > 0 && b.traffic().sent_datagrams > 0);
    assert_eq!(a.traffic().refused_datagrams, 0);
}

#[tokio::test]
async fn unknown_clients_and_a_real_tls_server_with_the_wrong_key_are_refused() {
    let a = endpoint();
    let b = endpoint();
    let to_b = admit(&a, &b);
    assert!(a.connect(&to_b, b.local_addr().unwrap()).await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), b.accept())
            .await
            .is_err()
    );
    let false_box_key = TransportKey::generate();
    let forged_destination = Card::sign(
        &false_box_key,
        now(),
        now() + 120,
        1,
        vec![Hint::udp(b.local_addr().unwrap())],
    );
    let wrong_pin = a
        .admit_peer(false_box_key.node_id(), forged_destination.as_bytes(), None)
        .unwrap();
    let _allow_a = admit(&b, &a);
    assert!(
        a.connect(&wrong_pin, b.local_addr().unwrap())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), b.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn tampered_expired_off_network_and_unselected_card_hints_send_no_packets() {
    let a = endpoint();
    let b = endpoint();
    let mut raw = card(&b, 1).as_bytes().to_vec();
    raw[40] ^= 1;
    assert!(a.admit_peer(b.node_id(), &raw, None).is_err());
    let key = TransportKey::generate();
    let expired = Card::sign(&key, now() - 10, now() - 1, 1, vec![]);
    assert!(
        a.admit_peer(key.node_id(), expired.as_bytes(), None)
            .is_err()
    );
    let off_network = Card::sign(
        &key,
        now(),
        now() + 120,
        2,
        vec![Hint::udp("192.0.2.1:443".parse().unwrap())],
    );
    let selected = a
        .admit_peer(key.node_id(), off_network.as_bytes(), None)
        .unwrap();
    assert!(matches!(
        a.connect(&selected, "192.0.2.1:443".parse().unwrap()).await,
        Err(LanError::Address)
    ));
    let to_b = admit(&a, &b);
    assert!(matches!(
        a.connect(&to_b, "127.0.0.1:1".parse().unwrap()).await,
        Err(LanError::Address)
    ));
    assert_eq!(a.traffic().sent_datagrams, 0);
    for bind in [
        "0.0.0.0:0",
        "224.0.0.1:0",
        "[::]:0",
        "[ff02::1]:0",
        "192.0.2.1:0",
    ] {
        assert!(
            LanEndpoint::open(
                TransportKey::generate(),
                LanBinding::Interface(bind.parse().unwrap())
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn a_relay_hint_is_not_permission_to_contact_that_relay() {
    let a = endpoint();
    let key = TransportKey::generate();
    let b_id = key.node_id();
    let server_key = TransportKey::from_seed(key.seed());
    let b = LanEndpoint::open(server_key, LanBinding::default()).unwrap();
    let trap = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let offered = Card::sign(
        &key,
        now(),
        now() + 120,
        1,
        vec![
            Hint::udp(b.local_addr().unwrap()),
            Hint::relay(&format!("ws://{}", trap.local_addr().unwrap())),
        ],
    );
    let to_b = a.admit_peer(b_id, offered.as_bytes(), None).unwrap();
    let _to_a = admit(&b, &a);
    let session = a.connect(&to_b, b.local_addr().unwrap()).await.unwrap();
    let accepted = b.accept().await.unwrap();
    assert!(session.is_live() && accepted.is_live());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), trap.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn revoked_admission_blocks_existing_streams_and_a_stale_handle_cannot_revoke_its_replacement()
 {
    let a = endpoint();
    let b = endpoint();
    let to_b = admit(&a, &b);
    let _to_a = admit(&b, &a);
    let session = a.connect(&to_b, b.local_addr().unwrap()).await.unwrap();
    let received = b.accept().await.unwrap();
    let mut stream = session.open_stream().await.unwrap();
    stream.write_all(b"first").await.unwrap();
    let mut incoming = received.accept_stream().await.unwrap();
    let mut first = [0; 5];
    incoming.read_exact(&mut first).await.unwrap();
    drop(to_b);
    assert!(!session.is_live());
    assert!(stream.write_all(b"after revocation").await.is_err());
    let old = a
        .admit_peer(b.node_id(), card(&b, 2).as_bytes(), None)
        .unwrap();
    let replacement = a
        .admit_peer(b.node_id(), card(&b, 3).as_bytes(), None)
        .unwrap();
    drop(old);
    let next = a
        .connect(&replacement, b.local_addr().unwrap())
        .await
        .unwrap();
    assert!(next.is_live());
    a.close();
    assert!(!next.is_live());
}

#[tokio::test]
async fn checkpoints_restore_only_exact_current_cards_and_refuse_conflicts_and_rollback() {
    let a = endpoint();
    let b = endpoint();
    let second = card(&b, 2);
    let checkpoint = verify_peer_card(b.node_id(), second.as_bytes(), None).unwrap();
    let admission = a
        .admit_peer(b.node_id(), second.as_bytes(), Some(&checkpoint))
        .unwrap();
    assert_eq!(admission.checkpoint(), &checkpoint);
    let mut corrupt = checkpoint.clone();
    corrupt.serial = 0;
    assert!(verify_peer_card(b.node_id(), second.as_bytes(), Some(&corrupt)).is_err());
    corrupt.serial = 1;
    assert!(verify_peer_card(b.node_id(), second.as_bytes(), Some(&corrupt)).is_err());
    assert!(
        a.admit_peer(b.node_id(), card(&b, 1).as_bytes(), None)
            .is_err()
    );
    let different = b.card(Duration::from_secs(119), 2).unwrap();
    assert!(verify_peer_card(b.node_id(), different.as_bytes(), Some(&checkpoint)).is_err());
    let fresh = endpoint();
    assert!(
        fresh
            .admit_peer(b.node_id(), second.as_bytes(), Some(&checkpoint))
            .is_ok()
    );
    assert!(verify_peer_card(a.node_id(), second.as_bytes(), Some(&checkpoint)).is_err());
}

#[tokio::test]
async fn first_contact_pins_the_box_and_exposes_only_one_provisional_stream() {
    let phone = endpoint();
    let window = Arc::new(
        LanPairingListener::open(
            TransportKey::generate(),
            LanBinding::default(),
            Duration::from_secs(10),
        )
        .unwrap(),
    );
    let offer = window.card(Duration::from_secs(10), 1).unwrap();
    let checkpoint = verify_peer_card(window.node_id(), offer.as_bytes(), None).unwrap();
    let server = window.clone();
    let serving = tokio::spawn(async move {
        let session = server.accept().await.unwrap();
        let provisional = session.provisional_peer();
        let mut stream = session.stream().await.unwrap();
        let mut request = [0; 16];
        stream.read_exact(&mut request).await.unwrap();
        // Synthetic application bytes. This does not claim Bothy claim adoption
        // or raw-secret authentication, which belong to Quill's integration.
        stream.write_all(&request).await.unwrap();
        stream.finish().await.unwrap();
        assert!(matches!(session.stream().await, Err(LanError::StreamLimit)));
        provisional
    });
    let session = phone
        .connect_pairing(
            window.node_id(),
            offer.as_bytes(),
            &checkpoint,
            window.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let mut stream = session.stream().await.unwrap();
    stream.write_all(&[23; 16]).await.unwrap();
    stream.finish().await.unwrap();
    let mut returned = Vec::new();
    stream.read_to_end(&mut returned).await.unwrap();
    assert_eq!(returned, [23; 16]);
    assert!(session.stream().await.is_err());
    assert_eq!(serving.await.unwrap(), phone.node_id());
    assert!(phone.traffic().sent_datagrams > 0 && window.traffic().sent_datagrams > 0);
}

#[tokio::test]
async fn ending_or_expiring_a_pairing_window_invalidates_its_streams() {
    let phone = endpoint();
    let window = LanPairingListener::open(
        TransportKey::generate(),
        LanBinding::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let offer = window.card(Duration::from_secs(3), 1).unwrap();
    let checkpoint = verify_peer_card(window.node_id(), offer.as_bytes(), None).unwrap();
    let client = phone
        .connect_pairing(
            window.node_id(),
            offer.as_bytes(),
            &checkpoint,
            window.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let accepted = window.accept().await.unwrap();
    let mut outgoing = client.stream().await.unwrap();
    outgoing.write_all(b"x").await.unwrap();
    let mut stream = accepted.stream().await.unwrap();
    window.close();
    assert!(!accepted.is_live());
    let mut byte = [0];
    assert!(stream.read_exact(&mut byte).await.is_err());
    assert!(window.accept().await.is_err());
    let short = LanPairingListener::open(
        TransportKey::generate(),
        LanBinding::default(),
        Duration::from_secs(1),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(short.card(Duration::from_secs(1), 1).is_err());
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn provisional_capacity_is_bounded_and_recovers_after_a_session_closes() {
    let window = LanPairingListener::open(
        TransportKey::generate(),
        LanBinding::default(),
        Duration::from_secs(30),
    )
    .unwrap();
    let offer = window.card(Duration::from_secs(30), 1).unwrap();
    let checkpoint = verify_peer_card(window.node_id(), offer.as_bytes(), None).unwrap();
    let mut phones = Vec::new();
    let mut clients = Vec::new();
    let mut servers = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let phone = endpoint();
        clients.push(
            phone
                .connect_pairing(
                    window.node_id(),
                    offer.as_bytes(),
                    &checkpoint,
                    window.local_addr().unwrap(),
                )
                .await
                .unwrap(),
        );
        servers.push(window.accept().await.unwrap());
        phones.push(phone);
    }
    let extra = endpoint();
    assert!(
        extra
            .connect_pairing(
                window.node_id(),
                offer.as_bytes(),
                &checkpoint,
                window.local_addr().unwrap()
            )
            .await
            .is_err()
    );
    clients.pop().unwrap().close();
    servers.pop().unwrap().close();
    let replacement = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match extra
                .connect_pairing(
                    window.node_id(),
                    offer.as_bytes(),
                    &checkpoint,
                    window.local_addr().unwrap(),
                )
                .await
            {
                Ok(session) => break session,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .unwrap();
    assert!(replacement.is_live());
    assert!(window.accept().await.unwrap().is_live());
}

#[tokio::test]
async fn pairing_streams_refuse_bytes_beyond_the_cap() {
    let phone = endpoint();
    let window = LanPairingListener::open(
        TransportKey::generate(),
        LanBinding::default(),
        Duration::from_secs(30),
    )
    .unwrap();
    let offer = window.card(Duration::from_secs(30), 1).unwrap();
    let checkpoint = verify_peer_card(window.node_id(), offer.as_bytes(), None).unwrap();
    let client = phone
        .connect_pairing(
            window.node_id(),
            offer.as_bytes(),
            &checkpoint,
            window.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let accepted = window.accept().await.unwrap();
    let sending = tokio::spawn(async move {
        let mut stream = client.stream().await.unwrap();
        assert!(
            stream
                .write_all(&vec![1; MAX_PAIRING_STREAM_BYTES as usize + 1])
                .await
                .is_err()
        );
        (client, stream)
    });
    let mut incoming = accepted.stream().await.unwrap();
    let mut bytes = Vec::new();
    assert!(incoming.read_to_end(&mut bytes).await.is_err());
    assert_eq!(bytes.len(), MAX_PAIRING_STREAM_BYTES as usize);
    sending.await.unwrap();
}

#[tokio::test]
async fn persisted_cards_and_keys_reconnect_after_both_endpoints_restart_locally() {
    let first_seed = [41; 32];
    let second_seed = [42; 32];
    let a = LanEndpoint::open(TransportKey::from_seed(first_seed), LanBinding::default()).unwrap();
    let b = LanEndpoint::open(TransportKey::from_seed(second_seed), LanBinding::default()).unwrap();
    let addr_a = a.local_addr().unwrap();
    let addr_b = b.local_addr().unwrap();
    let card_a = card(&a, 1);
    let card_b = card(&b, 1);
    let saved_a = verify_peer_card(a.node_id(), card_a.as_bytes(), None).unwrap();
    let saved_b = verify_peer_card(b.node_id(), card_b.as_bytes(), None).unwrap();
    let to_b = a
        .admit_peer(b.node_id(), card_b.as_bytes(), Some(&saved_b))
        .unwrap();
    let to_a = b
        .admit_peer(a.node_id(), card_a.as_bytes(), Some(&saved_a))
        .unwrap();
    let session = a.connect(&to_b, addr_b).await.unwrap();
    let peer = b.accept().await.unwrap();
    session.close();
    peer.close();
    drop(session);
    drop(peer);
    drop(to_b);
    drop(to_a);
    drop(a);
    drop(b);
    async fn restart(seed: [u8; 32], address: std::net::SocketAddr) -> LanEndpoint {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(endpoint) = LanEndpoint::open(
                    TransportKey::from_seed(seed),
                    LanBinding::LoopbackDevelopment(address),
                ) {
                    break endpoint;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("previous native listener must release its selected socket")
    }
    let a = restart(first_seed, addr_a).await;
    let b = restart(second_seed, addr_b).await;
    let to_b = a
        .admit_peer(b.node_id(), card_b.as_bytes(), Some(&saved_b))
        .unwrap();
    let _to_a = b
        .admit_peer(a.node_id(), card_a.as_bytes(), Some(&saved_a))
        .unwrap();
    let session = a.connect(&to_b, addr_b).await.unwrap();
    let peer = b.accept().await.unwrap();
    assert!(session.is_live() && peer.is_live());
}
