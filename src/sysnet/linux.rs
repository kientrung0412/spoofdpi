//! Linux integration: TUN device with policy routing via `ip`. There is no
//! desktop-agnostic system proxy, so proxy auto-configuration is a no-op.

use std::net::Ipv4Addr;

use tun::AbstractDevice;

use super::{ProxyKind, Route, TunSetup};
use crate::netutil::jobs::{cmd, run_command, NetworkJob};

pub const SUPPORTS_SYSTEM_PROXY: bool = false;
pub const SUPPORTS_TUN: bool = true;

pub fn is_elevated() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|v| v == "0"))
        })
        .unwrap_or(false)
}

pub fn refresh_proxy() -> Result<(), String> {
    Ok(())
}

pub fn build_proxy_jobs(_: ProxyKind, _: &Route, _: u16, _: &str) -> Result<Vec<NetworkJob>, String> {
    Ok(Vec::new())
}

fn find_table_id() -> Result<u32, String> {
    for id in 200..=250u32 {
        let id_s = id.to_string();
        match run_command(&cmd(["ip", "route", "show", "table", &id_s])) {
            Err(_) => return Ok(id),
            Ok(out) if !out.trim().is_empty() => continue,
            Ok(_) => {}
        }
        let rules = run_command(&cmd(["ip", "rule", "show", "table", &id_s])).unwrap_or_default();
        if rules.trim().is_empty() {
            return Ok(id);
        }
    }
    Err("no available routing table ID in range 200-250".into())
}

pub fn create_tun(route: &Route, local: Ipv4Addr, remote: Ipv4Addr) -> Result<TunSetup, String> {
    let mut config = tun::Configuration::default();
    config
        .tun_name("tun-spoofdpi")
        .address(local)
        .destination(remote)
        .netmask(Ipv4Addr::new(255, 255, 255, 252))
        .mtu(1500)
        .up();
    let device = tun::create_as_async(&config).map_err(|e| format!("failed to create tun device: {e}"))?;
    let name = device.tun_name().map_err(|e| e.to_string())?;

    let gateway = route
        .gateway
        .filter(|g| g.is_ipv4())
        .ok_or("no IPv4 default gateway found")?
        .to_string();
    let phys = route.iface_name.clone();
    let phys_ip = route
        .v4
        .ok_or("no IPv4 address on the default interface")?
        .to_string();
    let table = find_table_id()?.to_string();

    let mut jobs = vec![
        NetworkJob {
            description: "add gateway host route".into(),
            apply: cmd(["ip", "route", "add", &gateway, "dev", &phys]),
            reset: cmd(["ip", "route", "del", &gateway, "dev", &phys]),
        },
        NetworkJob {
            description: "add default route to routing table".into(),
            apply: cmd([
                "ip", "route", "add", "default", "via", &gateway, "dev", &phys, "table", &table,
            ]),
            reset: cmd(["ip", "route", "del", "default", "table", &table]),
        },
        NetworkJob {
            description: "add policy routing rule".into(),
            apply: cmd(["ip", "rule", "add", "from", &phys_ip, "lookup", &table]),
            reset: cmd(["ip", "rule", "del", "from", &phys_ip, "lookup", &table]),
        },
    ];
    for net in ["0.0.0.0/1", "128.0.0.0/1"] {
        jobs.push(NetworkJob {
            description: format!("add CIDR route {net} via TUN"),
            apply: cmd(["ip", "route", "add", net, "dev", &name]),
            reset: cmd(["ip", "route", "del", net, "dev", &name]),
        });
    }

    Ok(TunSetup { device, name, jobs })
}
