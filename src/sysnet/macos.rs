//! macOS integration: proxy auto-config through `networksetup`.

use std::net::Ipv4Addr;

use super::{ProxyKind, Route, TunSetup};
use crate::netutil::jobs::{cmd, run_command, NetworkJob};

pub const SUPPORTS_SYSTEM_PROXY: bool = true;
pub const SUPPORTS_TUN: bool = false;

pub fn is_elevated() -> bool {
    run_command(&cmd(["id", "-u"]))
        .map(|o| o.trim() == "0")
        .unwrap_or(false)
}

pub fn refresh_proxy() -> Result<(), String> {
    Ok(())
}

/// Maps a BSD device name (e.g. `en0`) to its network service name.
fn service_for_interface(iface: &str) -> Result<String, String> {
    let out = run_command(&cmd(["networksetup", "-listnetworkserviceorder"]))?;
    let mut last_service: Option<String> = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('(') {
            if let Some((idx, name)) = rest.split_once(')') {
                if idx.chars().all(|c| c.is_ascii_digit()) {
                    last_service = Some(name.trim().to_string());
                    continue;
                }
            }
            if line.contains(&format!("Device: {iface})")) {
                if let Some(s) = last_service.take() {
                    return Ok(s);
                }
            }
        }
    }
    Err(format!("no network service found for interface: {iface}"))
}

pub fn build_proxy_jobs(
    _: ProxyKind,
    route: &Route,
    _port: u16,
    pac_url: &str,
) -> Result<Vec<NetworkJob>, String> {
    let service = service_for_interface(&route.iface_name)
        .map_err(|e| format!("failed to get network service: {e}"))?;
    Ok(vec![
        NetworkJob {
            description: "set auto proxy URL".into(),
            apply: cmd(["networksetup", "-setautoproxyurl", &service, pac_url]),
            reset: cmd(["networksetup", "-setautoproxystate", &service, "off"]),
        },
        NetworkJob {
            description: "enable proxy auto discovery".into(),
            apply: cmd(["networksetup", "-setproxyautodiscovery", &service, "on"]),
            reset: cmd(["networksetup", "-setproxyautodiscovery", &service, "off"]),
        },
    ])
}

pub fn create_tun(_: &Route, _: Ipv4Addr, _: Ipv4Addr) -> Result<TunSetup, String> {
    Err("tun mode is not supported on macos".into())
}
