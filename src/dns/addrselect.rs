//! Simplified RFC 6724 destination address ordering: routable addresses
//! first, then by policy table precedence. The sort is stable.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

fn precedence(ip: IpAddr) -> u8 {
    let v6 = match ip {
        IpAddr::V4(v4) => return if v4.is_loopback() { 50 } else { 35 },
        IpAddr::V6(v6) => v6,
    };
    if v6 == Ipv6Addr::LOCALHOST {
        return 50;
    }
    let seg = v6.segments();
    if v6.to_ipv4_mapped().is_some() {
        35
    } else if seg[0] == 0x2002 {
        30
    } else if seg[0] == 0x2001 && seg[1] == 0 {
        5
    } else if seg[0] & 0xfe00 == 0xfc00 {
        3
    } else if (seg[0] & 0xffc0 == 0xfec0) || seg[0] == 0x3ffe || seg[..6].iter().all(|s| *s == 0) {
        1
    } else {
        40
    }
}

/// Whether the OS has a route to `ip` (a UDP connect sends no packets).
fn has_route(ip: IpAddr) -> bool {
    let bind: SocketAddr = if ip.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    UdpSocket::bind(bind)
        .and_then(|s| s.connect(SocketAddr::new(ip, 9)))
        .is_ok()
}

pub fn sort_by_rfc6724(addrs: &mut [IpAddr]) {
    if addrs.len() < 2 {
        return;
    }
    let mut keyed: Vec<(bool, u8, IpAddr)> = addrs
        .iter()
        .map(|ip| (has_route(*ip), precedence(*ip), *ip))
        .collect();
    keyed.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    for (slot, (_, _, ip)) in addrs.iter_mut().zip(keyed) {
        *slot = ip;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_table() {
        assert_eq!(precedence("::1".parse().unwrap()), 50);
        assert_eq!(precedence("1.2.3.4".parse().unwrap()), 35);
        assert_eq!(precedence("2606:4700::1".parse().unwrap()), 40);
        assert_eq!(precedence("fd00::1".parse().unwrap()), 3);
        assert_eq!(precedence("2002::1".parse().unwrap()), 30);
    }

    #[test]
    fn stable_for_same_family() {
        let mut v: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()];
        sort_by_rfc6724(&mut v);
        assert_eq!(v[0].to_string(), "1.1.1.1");
    }
}
