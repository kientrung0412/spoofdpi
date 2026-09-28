//! Windows integration: WinINet system proxy via the registry, Wintun TUN
//! device and `route` commands.

use std::net::Ipv4Addr;

use tun::AbstractDevice;

use super::{ProxyKind, Route, TunSetup};
use crate::netutil::jobs::{cmd, run_command, NetworkJob};

pub const SUPPORTS_SYSTEM_PROXY: bool = true;
pub const SUPPORTS_TUN: bool = true;

const INTERNET_SETTINGS: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Fixed adapter GUID so Windows does not create a new network profile on
/// every start.
const TUN_GUID: u128 = 0x5f0fd1a4_2c6e_4b8e_9b1d_73a05e9c0d01;

pub fn is_elevated() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

/// Tells running applications that the proxy settings changed.
pub fn refresh_proxy() -> Result<(), String> {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
    Ok(())
}

/// Reads a value under Internet Settings: `(type, data)`.
fn query_value(name: &str) -> Option<(String, String)> {
    let out = run_command(&cmd(["reg", "query", INTERNET_SETTINGS, "/v", name])).ok()?;
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some(name) {
            continue;
        }
        let ty = parts.next()?.to_string();
        // Data may contain spaces; take everything after the type column.
        let data = line
            .split_once(&ty)
            .map(|(_, rest)| rest.trim().to_string())
            .unwrap_or_default();
        return Some((ty, data));
    }
    None
}

fn set_value(name: &str, ty: &str, data: &str) -> Vec<String> {
    cmd([
        "reg",
        "add",
        INTERNET_SETTINGS,
        "/v",
        name,
        "/t",
        ty,
        "/d",
        data,
        "/f",
    ])
}

fn restore_value(name: &str, previous: &Option<(String, String)>) -> Vec<String> {
    match previous {
        Some((ty, data)) => set_value(name, ty, data),
        None => cmd(["reg", "delete", INTERNET_SETTINGS, "/v", name, "/f"]),
    }
}

fn value_job(name: &str, ty: &str, data: &str) -> NetworkJob {
    let prev = query_value(name);
    NetworkJob {
        description: format!("set {name}"),
        apply: set_value(name, ty, data),
        reset: restore_value(name, &prev),
    }
}

pub fn build_proxy_jobs(
    kind: ProxyKind,
    _route: &Route,
    port: u16,
    pac_url: &str,
) -> Result<Vec<NetworkJob>, String> {
    let mut jobs = vec![NetworkJob {
        description: "notify applications (reset)".into(),
        apply: Vec::new(),
        reset: cmd(["@refresh-proxy"]),
    }];

    match kind {
        ProxyKind::Http => {
            // A PAC URL takes precedence over the manual proxy; park it.
            if let Some(prev) = query_value("AutoConfigURL") {
                jobs.push(NetworkJob {
                    description: "disable proxy auto-config URL".into(),
                    apply: cmd(["reg", "delete", INTERNET_SETTINGS, "/v", "AutoConfigURL", "/f"]),
                    reset: restore_value("AutoConfigURL", &Some(prev)),
                });
            }
            jobs.push(value_job("ProxyServer", "REG_SZ", &format!("127.0.0.1:{port}")));
            jobs.push(value_job("ProxyOverride", "REG_SZ", "localhost;127.*;<local>"));
            jobs.push(value_job("ProxyEnable", "REG_DWORD", "1"));
        }
        ProxyKind::Socks5 => {
            // WinINet only speaks SOCKS4 for manual proxies; a PAC file
            // returning "SOCKS5" is honoured by Chromium-based browsers.
            jobs.push(value_job("AutoConfigURL", "REG_SZ", pac_url));
        }
    }

    jobs.push(NetworkJob {
        description: "notify applications".into(),
        apply: cmd(["@refresh-proxy"]),
        reset: Vec::new(),
    });
    Ok(jobs)
}

pub fn create_tun(route: &Route, local: Ipv4Addr, remote: Ipv4Addr) -> Result<TunSetup, String> {
    let _ = route;
    let mut config = tun::Configuration::default();
    config
        .tun_name("spoofdpi")
        .address(local)
        .netmask(Ipv4Addr::new(255, 255, 255, 252))
        .mtu(1500)
        .up();
    config.platform_config(|p| {
        p.device_guid(TUN_GUID);
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            p.wintun_file(dir.join("wintun.dll"));
        }
    });

    let device = tun::create_as_async(&config).map_err(|e| {
        format!("failed to create wintun adapter: {e} (wintun.dll must be next to spoofdpi.exe and spoofdpi must run as Administrator)")
    })?;
    let index = device.tun_index().map_err(|e| e.to_string())?;
    let name = device.tun_name().unwrap_or_else(|_| "spoofdpi".into());

    let remote_s = remote.to_string();
    let index_s = index.to_string();
    let mut jobs = Vec::new();
    for net in ["0.0.0.0", "128.0.0.0"] {
        jobs.push(NetworkJob {
            description: format!("add CIDR route {net}/1 via TUN"),
            apply: cmd([
                "route",
                "add",
                net,
                "mask",
                "128.0.0.0",
                &remote_s,
                "metric",
                "1",
                "if",
                &index_s,
            ]),
            reset: cmd(["route", "delete", net, "mask", "128.0.0.0", &remote_s]),
        });
    }

    Ok(TunSetup { device, name, jobs })
}
