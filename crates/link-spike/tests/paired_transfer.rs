//! Exercise both demo processes and inspect their WSS frames at a local relay.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use link_core::RelayAdmissionKey;
use link_core::wire::Frame;
use link_relay::{RelayAdmission, RelayConfig, TlsMaterial};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdout, Command};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::{Error, Message};

const MARKER: &[u8] = b"Link quickstart synthetic file marker";
const SENDER_KEY: [u8; 32] = [0x98; 32];
const RECEIVER_KEY: [u8; 32] = [0xa3; 32];

#[derive(Default)]
struct Frames {
    register: usize,
    routed: usize,
    identity: usize,
    fixture_in_clear: bool,
    key_in_clear: bool,
    proofs: HashSet<[u8; 32]>,
    repeat_proof: bool,
}

impl Frames {
    fn record(&mut self, message: &Message) -> Result<()> {
        let Message::Binary(bytes) = message else {
            return Ok(());
        };
        self.fixture_in_clear |= bytes.windows(MARKER.len()).any(|bytes| bytes == MARKER);
        self.key_in_clear |= bytes
            .windows(32)
            .any(|bytes| bytes == SENDER_KEY || bytes == RECEIVER_KEY);
        match Frame::decode(bytes).context("invalid relay frame")? {
            Frame::Register { .. } => self.register += 1,
            Frame::RegisterAdmitted { proof, .. } => {
                self.repeat_proof |= !self.proofs.insert(proof);
            }
            Frame::SendTag { .. } | Frame::RecvTag { .. } => self.routed += 1,
            Frame::Auth { .. } | Frame::Send { .. } | Frame::Recv { .. } => self.identity += 1,
            _ => {}
        }
        Ok(())
    }
}

async fn inspect_endpoint(
    tcp: TcpListener,
    tls: tokio_rustls::TlsAcceptor,
    backend: String,
    frames: Arc<Mutex<Frames>>,
) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            result = tcp.accept() => {
                let (stream, _) = result?;
                let tls = tls.clone();
                let backend = backend.clone();
                let frames = frames.clone();
                clients.spawn(async move {
                    let mut front = tokio_tungstenite::accept_async(tls.accept(stream).await?).await?;
                    let (mut back, _) = tokio_tungstenite::connect_async(backend).await?;
                    loop {
                        tokio::select! {
                            Some(Ok(message)) = front.next() => {
                                frames.lock().unwrap().record(&message)?;
                                back.send(message).await?;
                            }
                            Some(Ok(message)) = back.next() => {
                                frames.lock().unwrap().record(&message)?;
                                front.send(message).await?;
                            }
                            else => return Ok::<(), anyhow::Error>(()),
                        }
                    }
                });
            }
            result = clients.join_next(), if !clients.is_empty() => {
                if let Some(result) = result
                    && let Err(error) = result?
                {
                    match error.downcast_ref::<Error>() {
                        Some(Error::ConnectionClosed | Error::AlreadyClosed | Error::Io(_)) => {}
                        _ => return Err(error),
                    }
                }
            }
        }
    }
}

fn key_file(dir: &Path, key: &[u8; 32]) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new_in(dir)?;
    writeln!(file, "{}", hex::encode(key))?;
    Ok(file)
}

async fn transfer(save_pair: bool, private: bool) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = RelayConfig::default();
    let relay = if private {
        let policy = RelayAdmission::default();
        policy.replace_keys(vec![
            RelayAdmissionKey::from_bytes(SENDER_KEY),
            RelayAdmissionKey::from_bytes(RECEIVER_KEY),
        ])?;
        link_relay::start_with_admission(config, policy).await?
    } else {
        link_relay::start(config).await?
    };
    let material = TlsMaterial::self_signed(&["127.0.0.1".into()])?;
    let pin = material.fingerprint();
    let cert = CertificateDer::from(material.cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.key_der));
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    let front = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("wss://{}/link", front.local_addr()?);
    let frames = Arc::new(Mutex::new(Frames::default()));
    let observer = tokio::spawn(inspect_endpoint(
        front,
        Arc::new(tls).into(),
        relay.url("127.0.0.1"),
        frames.clone(),
    ));

    let dir = tempfile::tempdir()?;
    let input = dir.path().join("input.txt");
    let output = dir.path().join("output.txt");
    let receiver_state = dir.path().join("receiver.pair");
    let sender_state = dir.path().join("sender.pair");
    let credentials = if private {
        Some((
            key_file(dir.path(), &RECEIVER_KEY)?,
            key_file(dir.path(), &SENDER_KEY)?,
        ))
    } else {
        None
    };
    let bytes = MARKER.repeat(8192);
    std::fs::write(&input, &bytes)?;
    let cli = env!("CARGO_BIN_EXE_link-spike");
    let flags = ["--relay", &url, "--relay-cert-sha256", &pin];
    let mut receive = Command::new(cli);
    receive.arg("pair-receive").args(flags);
    if save_pair {
        receive.arg("--state").arg(&receiver_state);
    }
    if let Some((receiver_key, _)) = &credentials {
        receive
            .arg("--relay-admission-key-file")
            .arg(receiver_key.path());
    }
    let mut receiver = receive
        .arg(&output)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut receiver_stdout = BufReader::new(receiver.stdout.take().context("receive stdout")?);
    let mut invite = String::new();
    receiver_stdout.read_line(&mut invite).await?;
    let invite = invite
        .strip_prefix("invite ")
        .context("receiver did not print an invite")?;
    let mut send = Command::new(cli);
    send.arg("pair-send").args(flags);
    if save_pair {
        send.arg("--state").arg(&sender_state);
    }
    if let Some((_, sender_key)) = &credentials {
        send.arg("--relay-admission-key-file")
            .arg(sender_key.path());
    }
    let mut sender = send
        .arg(&input)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    sender
        .stdin
        .take()
        .context("send stdin")?
        .write_all(invite.as_bytes())
        .await?;
    check_transfer(sender, receiver, receiver_stdout, &bytes, &output).await?;

    if save_pair {
        let next_output = dir.path().join("after-restart.txt");
        let next_bytes = MARKER.repeat(1024);
        std::fs::write(&input, &next_bytes)?;
        let mut receiver = Command::new(cli)
            .args(["saved-receive", "--state"])
            .arg(&receiver_state)
            .arg(&next_output)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut receiver_stdout = BufReader::new(receiver.stdout.take().context("receive stdout")?);
        let mut ready = String::new();
        receiver_stdout.read_line(&mut ready).await?;
        ensure!(
            ready.trim() == "ready for paired transfer",
            "saved receiver did not become ready"
        );
        let sender = Command::new(cli)
            .args(["saved-send", "--state"])
            .arg(&sender_state)
            .arg(&input)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        check_transfer(sender, receiver, receiver_stdout, &next_bytes, &next_output).await?;

        let collision = Command::new(cli)
            .args(["saved-receive", "--state"])
            .arg(&receiver_state)
            .arg(&output)
            .kill_on_drop(true)
            .output()
            .await?;
        ensure!(!collision.status.success());
        ensure!(std::str::from_utf8(&collision.stderr)?.contains("output file already exists"));
        assert_eq!(
            std::fs::read(&output)?,
            bytes,
            "original file was preserved"
        );
    }

    ensure!(!observer.is_finished(), "relay observation stopped early");
    observer.abort();
    relay.shutdown();

    let frames = frames.lock().unwrap();
    assert!(frames.register > 0 && frames.routed > 0);
    assert_eq!(frames.identity, 0);
    assert!(!frames.fixture_in_clear);
    assert!(!frames.key_in_clear);
    assert!(!frames.repeat_proof);
    if private {
        assert!(
            frames.proofs.len() >= 4,
            "each first and restored connection proves its grant"
        );
    } else {
        assert!(frames.proofs.is_empty());
    }
    println!(
        "Relay decoded {} registrations, {} fresh admission proofs and {} tagged data frames. Zero identity frames, raw keys or clear file markers.",
        frames.register,
        frames.proofs.len(),
        frames.routed
    );
    Ok(())
}

async fn check_transfer(
    sender: Child,
    receiver: Child,
    mut receiver_stdout: BufReader<ChildStdout>,
    bytes: &[u8],
    output: &Path,
) -> Result<()> {
    let mut receipt = String::new();
    let (sender, receiver, _) = tokio::try_join!(
        sender.wait_with_output(),
        receiver.wait_with_output(),
        receiver_stdout.read_to_string(&mut receipt)
    )?;
    ensure!(
        sender.status.success(),
        "send failed: {}",
        String::from_utf8_lossy(&sender.stderr)
    );
    ensure!(
        receiver.status.success(),
        "receive failed: {}",
        String::from_utf8_lossy(&receiver.stderr)
    );
    ensure!(
        std::str::from_utf8(&sender.stdout)?.contains("path=relayed")
            && receipt.contains("path=relayed"),
        "both peers must record the relay path"
    );
    assert_eq!(std::fs::read(output)?, bytes, "verified file bytes");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paired_cli_uses_tag_routing_for_a_verified_file() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(25), transfer(false, false))
        .await
        .context("paired transfer timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paired_cli_transfers_again_after_both_peers_restart() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(25), transfer(true, false))
        .await
        .context("saved pairing transfer timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paired_cli_reproves_admission_after_both_peers_restart() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(25), transfer(true, true))
        .await
        .context("admitted pairing transfer timed out")?
}
