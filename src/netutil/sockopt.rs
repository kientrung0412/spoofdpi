//! Socket option helpers.

use std::io;

use socket2::SockRef;

/// Reads the unicast TTL (IPv4) or hop limit (IPv6).
pub fn ttl(sock: SockRef<'_>, ipv4: bool) -> io::Result<u32> {
    if ipv4 {
        sock.ttl_v4()
    } else {
        sock.unicast_hops_v6()
    }
}

/// Sets the unicast TTL (IPv4) or hop limit (IPv6).
pub fn set_ttl(sock: SockRef<'_>, ipv4: bool, ttl: u32) -> io::Result<()> {
    if ipv4 {
        sock.set_ttl_v4(ttl)
    } else {
        sock.set_unicast_hops_v6(ttl)
    }
}

/// Forces outbound traffic of the socket through the given interface
/// (`IP_UNICAST_IF` / `IPV6_UNICAST_IF`).
#[cfg(windows)]
pub fn set_unicast_if(sock: &SockRef<'_>, ipv4: bool, index: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPV6_UNICAST_IF, IP_UNICAST_IF};

    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;

    // IPv4 expects the index in network byte order, IPv6 in host order.
    let (level, name, value) = if ipv4 {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    };
    let raw = sock.as_raw_socket() as usize;
    let rc = unsafe {
        setsockopt(
            raw,
            level,
            name,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
