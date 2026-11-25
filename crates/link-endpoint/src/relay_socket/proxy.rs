//! SOCKS5 CONNECT with either no authentication or required Tor isolation.

use std::net::{IpAddr, SocketAddr};

use anyhow::ensure;
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

/// The trusted SOCKS5 server required for all native relay sockets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayProxy {
    /// Use a SOCKS5 server that accepts the no-authentication method.
    Socks5(SocketAddr),
    /// Require Tor's username/password stream isolation. Each relay socket
    /// requests a fresh isolation group.
    Tor(SocketAddr),
}

impl RelayProxy {
    pub(crate) fn address(self) -> SocketAddr {
        match self {
            Self::Socks5(address) | Self::Tor(address) => address,
        }
    }

    pub(super) async fn connect(self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        // Connect to the literal proxy address. The destination hostname is
        // only used as SOCKS request data and never passed to the resolver.
        let mut stream = TcpStream::connect(self.address()).await?;
        stream.set_nodelay(true).ok();

        let method = match self {
            Self::Socks5(_) => 0x00,
            Self::Tor(_) => 0x02,
        };
        stream.write_all(&[5, 1, method]).await?;
        let mut selection = [0; 2];
        stream.read_exact(&mut selection).await?;
        ensure!(selection == [5, method], "SOCKS5 rejected required method");
        if method == 0x02 {
            authenticate_for_tor(&mut stream).await?;
        }

        let mut request = vec![5, 1, 0]; // version, CONNECT, reserved
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                request.push(3);
                request.push(u8::try_from(host.len())?);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await?;

        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await?;
        let [version, status, reserved, address_type] = reply;
        ensure!(
            version == 5 && reserved == 0,
            "invalid SOCKS5 CONNECT reply"
        );
        ensure!(
            status == 0,
            "SOCKS5 CONNECT failed with status 0x{status:02x}"
        );
        // Consume exactly the remaining address and port so the TLS stream
        // starts at the correct byte. The bound address is not used.
        let address_len = match address_type {
            1 => 4,
            3 => usize::from(stream.read_u8().await?),
            4 => 16,
            _ => anyhow::bail!("invalid SOCKS5 reply address type"),
        };
        ensure!(address_len != 0, "empty SOCKS5 reply address");
        stream.read_exact(&mut [0; 257][..address_len + 2]).await?;
        Ok(stream)
    }
}

async fn authenticate_for_tor(stream: &mut TcpStream) -> anyhow::Result<()> {
    // Tor defines a type-0 username with the isolation label in the
    // password. Use fresh random values without exposing them to logs.
    const USERNAME: &[u8] = b"<torS0X>0";
    const LABEL_LEN: u8 = 24;
    let mut request = Zeroizing::new(vec![1, USERNAME.len() as u8]);
    request.extend_from_slice(USERNAME);
    request.push(LABEL_LEN);
    request.extend(OsRng.sample_iter(Alphanumeric).take(usize::from(LABEL_LEN)));
    stream.write_all(&request).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    ensure!(reply == [1, 0], "SOCKS5 rejected Tor isolation");
    Ok(())
}
