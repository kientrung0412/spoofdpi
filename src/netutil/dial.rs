//! Outbound connection helpers.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Pins outbound sockets to a physical interface so that TUN mode traffic
/// does not loop back into the TUN device.
#[derive(Clone, Debug)]
pub struct BindSpec {
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
    pub iface_index: u32,
    pub iface_name: String,
    pub v4: Option<std::net::Ipv4Addr>,
    pub v6: Option<std::net::Ipv6Addr>,
}

impl BindSpec {
    fn source_for(&self, target: IpAddr) -> Option<IpAddr> {
        match target {
            IpAddr::V4(_) => self.v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.v6.map(IpAddr::V6),
        }
    }

    /// Applies interface pinning to a socket before it is bound/connected.
    fn apply(&self, sock: SockRef<'_>, target: IpAddr) -> io::Result<()> {
        #[cfg(windows)]
        {
            let _ = &sock;
            super::sockopt::set_unicast_if(&sock, target.is_ipv4(), self.iface_index)?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let _ = target;
            sock.bind_device(Some(self.iface_name.as_bytes()))?;
        }
        #[cfg(target_os = "macos")]
        {
            let idx = std::num::NonZeroU32::new(self.iface_index);
            if target.is_ipv4() {
                sock.bind_device_by_index_v4(idx)?;
            } else {
                sock.bind_device_by_index_v6(idx)?;
            }
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android", target_os = "macos")))]
        {
            let _ = (sock, target);
        }
        Ok(())
    }
}

async fn connect_tcp(addr: SocketAddr, bind: Option<&BindSpec>) -> io::Result<TcpStream> {
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(b) = bind {
        b.apply(SockRef::from(&sock), addr.ip())?;
        match b.source_for(addr.ip()) {
            Some(src) => sock.bind(SocketAddr::new(src, 0))?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!(
                        "no suitable IP address found on interface {} for target {}",
                        b.iface_name,
                        addr.ip()
                    ),
                ))
            }
        }
    }
    let stream = sock.connect(addr).await?;
    // Every write must leave as its own segment for split/disorder to work.
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Connects to every address concurrently (at most 10 in flight) and returns
/// the first connection that succeeds. `timeout` of zero disables it.
pub async fn dial_tcp_fastest(
    addrs: &[IpAddr],
    port: u16,
    timeout: Duration,
    bind: Option<&Arc<BindSpec>>,
) -> io::Result<TcpStream> {
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no addresses provided to dial",
        ));
    }

    const MAX_CONCURRENCY: usize = 10;
    let mut pending = addrs.iter().copied();
    let mut in_flight = FuturesUnordered::new();

    let spawn = |ip: IpAddr| {
        let bind = bind.cloned();
        async move {
            let addr = SocketAddr::new(ip, port);
            let fut = connect_tcp(addr, bind.as_deref());
            if timeout.is_zero() {
                fut.await
            } else {
                match tokio::time::timeout(timeout, fut).await {
                    Ok(r) => r,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("dial tcp {addr}: i/o timeout"),
                    )),
                }
            }
        }
    };

    for ip in pending.by_ref().take(MAX_CONCURRENCY) {
        in_flight.push(spawn(ip));
    }

    let mut first_err: Option<io::Error> = None;
    let mut failures = 0usize;
    while let Some(res) = in_flight.next().await {
        match res {
            Ok(s) => return Ok(s),
            Err(e) => {
                failures += 1;
                first_err.get_or_insert(e);
                if let Some(ip) = pending.next() {
                    in_flight.push(spawn(ip));
                }
            }
        }
    }
    let e = first_err.unwrap();
    Err(io::Error::new(
        e.kind(),
        format!("all connection attempts failed (total {failures}): {e}"),
    ))
}

/// Creates a UDP socket connected to `addr`.
pub async fn dial_udp(addr: SocketAddr, bind: Option<&Arc<BindSpec>>) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    let src = match bind {
        Some(b) => {
            b.apply(SockRef::from(&sock), addr.ip())?;
            b.source_for(addr.ip())
        }
        None => None,
    };
    let src = src.unwrap_or(if addr.is_ipv4() {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    });
    sock.bind(&SocketAddr::new(src, 0).into())?;
    let udp = UdpSocket::from_std(sock.into())?;
    udp.connect(addr).await?;
    Ok(udp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fastest_skips_dead_addresses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        // 127.0.0.2 usually refuses on this port; 127.0.0.1 accepts.
        let addrs: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let s = dial_tcp_fastest(&addrs, port, Duration::from_secs(2), None)
            .await
            .unwrap();
        assert_eq!(s.peer_addr().unwrap().port(), port);
        assert!(s.nodelay().unwrap());
    }

    #[tokio::test]
    async fn fastest_reports_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = dial_tcp_fastest(&["127.0.0.1".parse().unwrap()], port, Duration::ZERO, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("all connection attempts failed"));
    }
}
