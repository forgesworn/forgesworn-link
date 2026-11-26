use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use link_core::admission::registration_digest;
use link_core::rendezvous::Tag;
use link_core::wire::{CLOSE_REASON_ADMISSION, CLOSE_REASON_MALFORMED, Frame, sign_relay_auth};
use link_core::{RelayAdmissionKey, TransportKey};
use link_relay::{RelayAdmission, RelayConfig, RelayHandle};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
const TAG: Tag = Tag([0x17; 16]);
const OTHER_TAG: Tag = Tag([0x20; 16]);

fn request(key: &RelayAdmissionKey, challenge: [u8; 32], tags: Vec<Tag>) -> Frame {
    let proof = key.proof(&challenge, &registration_digest(&tags));
    Frame::RegisterAdmitted { proof, tags }
}

async fn open(relay: &RelayHandle, private: bool) -> Result<(Socket, [u8; 32])> {
    // Plain loopback is the backend of a trusted TLS terminator in this fixture.
    let (mut socket, _) = tokio_tungstenite::connect_async(relay.url("127.0.0.1")).await?;
    let challenge = match (receive(&mut socket).await?, private) {
        (Frame::AdmissionChallenge(challenge), true) | (Frame::Challenge(challenge), false) => {
            challenge
        }
        _ => anyhow::bail!("expected challenge for the configured relay mode"),
    };
    Ok((socket, challenge))
}

async fn send(socket: &mut Socket, frame: Frame) -> Result<()> {
    Ok(socket.send(Message::Binary(frame.encode())).await?)
}

async fn receive(socket: &mut Socket) -> Result<Frame> {
    let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await?
        .context("relay socket closed")??;
    let Message::Binary(bytes) = message else {
        anyhow::bail!("expected binary relay frame")
    };
    Frame::decode(&bytes).context("expected a valid relay frame")
}

async fn admit(relay: &RelayHandle, key: &RelayAdmissionKey) -> Result<Socket> {
    let (mut socket, challenge) = open(relay, true).await?;
    send(&mut socket, request(key, challenge, vec![TAG])).await?;
    assert!(matches!(receive(&mut socket).await?, Frame::Welcome(_)));
    Ok(socket)
}

#[tokio::test]
async fn private_relay_accepts_only_a_current_proof_for_its_roster() -> Result<()> {
    let accepted = RelayAdmissionKey::from_bytes([4; 32]);
    let unknown = RelayAdmissionKey::from_bytes([5; 32]);
    let policy = RelayAdmission::default();
    policy.replace_keys(vec![accepted.clone()])?;
    let relay = link_relay::start_with_admission(RelayConfig::default(), policy).await?;

    let (mut socket, fresh) = open(&relay, true).await?;
    send(&mut socket, Frame::Register { tags: vec![TAG] }).await?;
    assert_eq!(
        receive(&mut socket).await?,
        Frame::Close(CLOSE_REASON_ADMISSION)
    );

    let (mut socket, challenge) = open(&relay, true).await?;
    let identity = TransportKey::generate();
    let signature = sign_relay_auth(&identity, "127.0.0.1", &challenge);
    send(
        &mut socket,
        Frame::Auth {
            node_id: identity.node_id(),
            signature,
        },
    )
    .await?;
    assert_eq!(
        receive(&mut socket).await?,
        Frame::Close(CLOSE_REASON_ADMISSION)
    );

    let (mut socket, challenge) = open(&relay, true).await?;
    send(&mut socket, request(&unknown, challenge, vec![TAG])).await?;
    assert_eq!(
        receive(&mut socket).await?,
        Frame::Close(CLOSE_REASON_ADMISSION)
    );

    let (mut socket, challenge) = open(&relay, true).await?;
    assert_ne!(fresh, challenge);
    send(&mut socket, request(&accepted, fresh, vec![TAG])).await?;
    assert_eq!(
        receive(&mut socket).await?,
        Frame::Close(CLOSE_REASON_ADMISSION)
    );

    let (mut socket, challenge) = open(&relay, true).await?;
    let proof = accepted.proof(&challenge, &registration_digest(&[TAG]));
    send(
        &mut socket,
        Frame::RegisterAdmitted {
            proof,
            tags: vec![OTHER_TAG],
        },
    )
    .await?;
    assert_eq!(
        receive(&mut socket).await?,
        Frame::Close(CLOSE_REASON_ADMISSION)
    );

    admit(&relay, &accepted).await?;
    relay.shutdown();
    let ordinary = link_relay::start(RelayConfig::default()).await?;
    let (mut socket, challenge) = open(&ordinary, false).await?;
    send(&mut socket, request(&accepted, challenge, vec![TAG])).await?;
    assert_eq!(
        receive(&mut socket).await?,
        Frame::Close(CLOSE_REASON_MALFORMED)
    );
    ordinary.shutdown();
    Ok(())
}

#[tokio::test]
async fn removing_a_grant_displaces_its_live_sockets_and_refuses_reconnect() -> Result<()> {
    let first = RelayAdmissionKey::from_bytes([6; 32]);
    let second = RelayAdmissionKey::from_bytes([7; 32]);
    let policy = RelayAdmission::default();
    policy.replace_keys(vec![first.clone(), second.clone()])?;
    let relay = link_relay::start_with_admission(RelayConfig::default(), policy.clone()).await?;
    let mut a = admit(&relay, &first).await?;
    let mut b = admit(&relay, &second).await?;
    let datagram = vec![1, 2, 3, 4];
    send(
        &mut a,
        Frame::SendTag {
            tag: TAG,
            datagram: datagram.clone(),
        },
    )
    .await?;
    assert_eq!(
        receive(&mut b).await?,
        Frame::RecvTag { tag: TAG, datagram }
    );

    assert!(
        policy
            .replace_keys(vec![second.clone(), second.clone()])
            .is_err()
    );
    // The other valid grant remains live across a successful replacement.
    policy.replace_keys(vec![second.clone()])?;
    assert_eq!(receive(&mut a).await?, Frame::Close(CLOSE_REASON_ADMISSION));
    send(&mut b, Frame::Ping([3; 8])).await?;
    assert_eq!(receive(&mut b).await?, Frame::Pong([3; 8]));

    let (mut retry, challenge) = open(&relay, true).await?;
    send(&mut retry, request(&first, challenge, vec![TAG])).await?;
    assert_eq!(
        receive(&mut retry).await?,
        Frame::Close(CLOSE_REASON_ADMISSION)
    );

    policy.replace_keys(vec![])?;
    assert_eq!(receive(&mut b).await?, Frame::Close(CLOSE_REASON_ADMISSION));
    relay.shutdown();
    Ok(())
}
