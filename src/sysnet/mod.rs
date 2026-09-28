//! OS integration: default route discovery, system proxy configuration and
//! TUN device setup.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod other;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
use other as os;
#[cfg(windows)]
use windows as os;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;

use crate::netutil::jobs::NetworkJob;
use crate::netutil::BindSpec;

/// The interface and gateway used for the default route.
#[derive(Clone, Debug)]
pub struct Route {
    pub iface_index: u32,
    pub iface_name: String,
    /// Human readable interface name (e.g. "Wi-Fi" on Windows).
    pub display_name: String,
    pub mac: Option<String>,
    pub gateway: Option<IpAddr>,
    pub gateway_mac: Option<String>,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

impl Route {
    pub fn bind_spec(&self) -> Arc<BindSpec> {
        Arc::new(BindSpec {
            iface_index: self.iface_index,
            iface_name: self.iface_name.clone(),
            v4: self.v4,
            v6: self.v6,
        })
    }
}

/// Local source address the OS would use to reach the internet
/// (a UDP connect sends no packets).
fn outbound_ipv4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

fn default_interface() -> Result<netdev::Interface, String> {
    match netdev::get_default_interface() {
        Ok(i) => Ok(i),
        Err(e) => {
            // Fall back to the interface owning the outbound source address.
            let ip = outbound_ipv4().ok_or_else(|| format!("discover interface: {e}"))?;
            netdev::get_interfaces()
                .into_iter()
                .find(|i| i.ipv4.iter().any(|n| n.addr() == ip))
                .ok_or_else(|| format!("discover interface: {e}; no interface owns {ip}"))
        }
    }
}

/// A route that only records the outbound address; used when discovery
/// fails but nothing depends on the interface.
pub fn fallback_route() -> Route {
    Route {
        iface_index: 0,
        iface_name: String::new(),
        display_name: "unknown".into(),
        mac: None,
        gateway: None,
        gateway_mac: None,
        v4: outbound_ipv4(),
        v6: None,
    }
}

pub fn discover_route() -> Result<Route, String> {
    let iface = default_interface()?;
    let v4 = iface.ipv4.first().map(|n| n.addr());
    let v6 = iface
        .ipv6
        .iter()
        .map(|n| n.addr())
        .find(|a| (a.segments()[0] & 0xffc0) != 0xfe80 && !a.is_loopback());
    let gateway = iface.gateway.as_ref().and_then(|g| {
        g.ipv4
            .first()
            .map(|a| IpAddr::V4(*a))
            .or_else(|| g.ipv6.first().map(|a| IpAddr::V6(*a)))
    });
    Ok(Route {
        iface_index: iface.index,
        display_name: iface.friendly_name.clone().unwrap_or_else(|| iface.name.clone()),
        iface_name: iface.name.clone(),
        mac: iface.mac_addr.map(|m| m.to_string()),
        gateway,
        gateway_mac: iface.gateway.as_ref().map(|g| g.mac_addr.to_string()),
        v4,
        v6,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Socks5,
}

fn state_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::temp_dir()
    } else {
        PathBuf::from("/tmp")
    }
}

/// State file for the system proxy jobs, `None` when the platform has no
/// system proxy integration.
pub fn proxy_state_file(kind: ProxyKind) -> Option<PathBuf> {
    if !os::SUPPORTS_SYSTEM_PROXY {
        return None;
    }
    let name = match kind {
        ProxyKind::Http => format!("spoofdpi.http.{}.state", std::env::consts::OS),
        ProxyKind::Socks5 => format!("spoofdpi.socks5.{}.state", std::env::consts::OS),
    };
    Some(state_dir().join(name))
}

pub fn tun_state_file() -> Option<PathBuf> {
    if !os::SUPPORTS_TUN {
        return None;
    }
    Some(state_dir().join(format!("spoofdpi.{}.tun.state", std::env::consts::OS)))
}

/// Jobs that point the system proxy at `listen_port`, or at `pac_url`.
pub fn build_proxy_jobs(
    kind: ProxyKind,
    route: &Route,
    listen_port: u16,
    pac_url: &str,
) -> Result<Vec<NetworkJob>, String> {
    os::build_proxy_jobs(kind, route, listen_port, pac_url)
}

/// Handles `@name` job commands.
pub fn run_internal(name: &str, args: &[String]) -> Result<(), String> {
    match name {
        "refresh-proxy" => os::refresh_proxy(),
        other => Err(format!("unknown internal command @{other} {args:?}")),
    }
}

/// A created TUN device together with the routing jobs that steer traffic
/// into it.
pub struct TunSetup {
    pub device: tun::AsyncDevice,
    pub name: String,
    pub jobs: Vec<NetworkJob>,
}

pub fn create_tun(route: &Route) -> Result<TunSetup, String> {
    if !os::SUPPORTS_TUN {
        return Err(format!("tun mode is not supported on {}", std::env::consts::OS));
    }
    let cidr = crate::netutil::find_safe_cidr()?;
    let local = crate::netutil::addr_in_cidr(&cidr, 1)?;
    let remote = crate::netutil::addr_in_cidr(&cidr, 2)?;
    os::create_tun(route, local, remote)
}

/// Whether the process has administrator/root privileges.
pub fn is_elevated() -> bool {
    os::is_elevated()
}
