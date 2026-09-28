//! Platforms without system proxy or TUN integration.

use std::net::Ipv4Addr;

use super::{ProxyKind, Route, TunSetup};
use crate::netutil::jobs::NetworkJob;

pub const SUPPORTS_SYSTEM_PROXY: bool = false;
pub const SUPPORTS_TUN: bool = false;

pub fn is_elevated() -> bool {
    false
}

pub fn refresh_proxy() -> Result<(), String> {
    Ok(())
}

pub fn build_proxy_jobs(_: ProxyKind, _: &Route, _: u16, _: &str) -> Result<Vec<NetworkJob>, String> {
    Ok(Vec::new())
}

pub fn create_tun(_: &Route, _: Ipv4Addr, _: Ipv4Addr) -> Result<TunSetup, String> {
    Err(format!("tun mode is not supported on {}", std::env::consts::OS))
}
