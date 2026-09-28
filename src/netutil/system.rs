//! Host network helpers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// All addresses assigned to local interfaces, with prefix lengths.
pub fn interface_nets() -> Vec<(IpAddr, u8)> {
    let mut out = Vec::new();
    for iface in netdev::get_interfaces() {
        out.extend(iface.ipv4.iter().map(|n| (IpAddr::V4(n.addr()), n.prefix_len())));
        out.extend(iface.ipv6.iter().map(|n| (IpAddr::V6(n.addr()), n.prefix_len())));
    }
    out
}

/// Rejects destinations that would make the proxy connect to itself.
pub fn is_valid_destination(addrs: &[IpAddr], port: u16, listen: SocketAddr) -> Result<(), String> {
    if port != listen.port() {
        return Ok(());
    }
    let local: Vec<IpAddr> = interface_nets().into_iter().map(|(ip, _)| ip).collect();
    for ip in addrs {
        if ip.is_loopback() {
            return Err(format!("loopback addr detected {ip}"));
        }
        if local.contains(ip) {
            return Err(format!("interface addr detected {ip}"));
        }
    }
    Ok(())
}

fn net_contains(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    net.is_ipv4() == ip.is_ipv4() && crate::config::mask_ip(net, len) == crate::config::mask_ip(ip, len)
}

/// Finds a free `10.x.y.0/30` that does not overlap any local network.
pub fn find_safe_cidr() -> Result<String, String> {
    let nets = interface_nets();
    for i in 0..=255u8 {
        for j in 0..=255u8 {
            let local = IpAddr::V4(Ipv4Addr::new(10, i, j, 1));
            let remote = IpAddr::V4(Ipv4Addr::new(10, i, j, 2));
            let conflict = nets
                .iter()
                .any(|(n, l)| net_contains(*n, *l, local) || net_contains(*n, *l, remote));
            if !conflict {
                return Ok(format!("10.{i}.{j}.0/30"));
            }
        }
    }
    Err("failed to find an available address in 10.0.0.0/8".into())
}

/// Returns the `n`-th address of an IPv4 CIDR.
pub fn addr_in_cidr(cidr: &str, n: u32) -> Result<Ipv4Addr, String> {
    let (net, len) = crate::config::parse_cidr(cidr)?;
    let IpAddr::V4(v4) = net else {
        return Err("not an IPv4 CIDR".into());
    };
    let ip = Ipv4Addr::from(u32::from(v4).wrapping_add(n));
    if !net_contains(net, len, IpAddr::V4(ip)) {
        return Err(format!("index {n} is out of CIDR range {cidr}"));
    }
    Ok(ip)
}

/// Serves `content` as a proxy auto-config file on a random local port until
/// `cancel` fires. Returns the PAC URL.
pub async fn run_pac_server(content: String, cancel: CancellationToken) -> std::io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = cancel.cancelled() => return,
                r = listener.accept() => r,
            };
            let Ok((mut conn, _)) = accepted else { continue };
            let body = content.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.read(&mut buf)).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = conn.write_all(resp.as_bytes()).await;
                let _ = conn.shutdown().await;
            });
        }
    });
    Ok(format!("http://127.0.0.1:{port}/proxy.pac"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nth_addr() {
        assert_eq!(
            addr_in_cidr("10.1.2.0/30", 1).unwrap(),
            Ipv4Addr::new(10, 1, 2, 1)
        );
        assert_eq!(
            addr_in_cidr("10.1.2.0/30", 2).unwrap(),
            Ipv4Addr::new(10, 1, 2, 2)
        );
        assert!(addr_in_cidr("10.1.2.0/30", 4).is_err());
    }

    #[test]
    fn safe_cidr_is_private() {
        let c = find_safe_cidr().unwrap();
        assert!(c.starts_with("10.") && c.ends_with("/30"));
    }

    #[test]
    fn self_loop_detection() {
        let listen: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(is_valid_destination(&["127.0.0.1".parse().unwrap()], 8080, listen).is_err());
        assert!(is_valid_destination(&["127.0.0.1".parse().unwrap()], 443, listen).is_ok());
        assert!(is_valid_destination(&["93.184.216.34".parse().unwrap()], 8080, listen).is_ok());
    }

    #[tokio::test]
    async fn pac_server_serves_content() {
        let cancel = CancellationToken::new();
        let url = run_pac_server("function FindProxyForURL(){}".into(), cancel.clone())
            .await
            .unwrap();
        let addr = url.trim_start_matches("http://").trim_end_matches("/proxy.pac");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /proxy.pac HTTP/1.1\r\n\r\n").await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.contains("application/x-ns-proxy-autoconfig"));
        assert!(out.ends_with("function FindProxyForURL(){}"));
        cancel.cancel();
    }
}
