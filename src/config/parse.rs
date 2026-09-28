//! Value parsers and validators shared by the TOML and CLI layers.

use std::net::{IpAddr, SocketAddr};

pub fn check_one_of(v: &str, allowed: &[&str]) -> Result<(), String> {
    if allowed.contains(&v) {
        Ok(())
    } else {
        Err(format!(
            "value '{v}' is invalid (allowed: {})",
            allowed.join(", ")
        ))
    }
}

pub fn int_range(v: i64, min: i64, max: i64) -> Result<i64, String> {
    if v < min || v > max {
        Err(format!("value {v} out of range[{min}-{max}]"))
    } else {
        Ok(v)
    }
}

pub fn check_uint8(v: i64) -> Result<u8, String> {
    int_range(v, 0, u8::MAX as i64).map(|v| v as u8)
}

pub fn check_uint8_non_zero(v: i64) -> Result<u8, String> {
    int_range(v, 1, u8::MAX as i64).map(|v| v as u8)
}

pub fn check_uint16(v: i64) -> Result<u16, String> {
    int_range(v, 0, u16::MAX as i64).map(|v| v as u16)
}

pub fn check_freebsd_fib(v: i64) -> Result<i64, String> {
    int_range(v, 1, 15)
}

/// Parses `ip:port` (IPv6 in brackets). The host must be an IP address.
pub fn parse_host_port(v: &str) -> Result<SocketAddr, String> {
    let (host, port) = v
        .rsplit_once(':')
        .ok_or_else(|| format!("address {v}: missing port in address"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let ip: IpAddr = host
        .parse()
        .map_err(|_| "invalid IP address format".to_string())?;
    let port: i64 = port
        .parse()
        .map_err(|_| format!("strconv.Atoi: parsing {port:?}: invalid syntax"))?;
    let port = check_uint16(port)?;
    Ok(SocketAddr::new(ip, port))
}

pub fn check_https_endpoint(v: &str) -> Result<(), String> {
    if v.is_empty() || v.starts_with("https://") || v.starts_with("http://") {
        Ok(())
    } else {
        Err("should start with 'https://'".into())
    }
}

/// Parses a comma separated list of `0xHH` bytes, e.g. `0x16, 0x03, 0x01`.
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for part in trimmed.split(',') {
        let p = part.trim();
        let hex = p
            .strip_prefix("0x")
            .filter(|h| h.len() == 2 && h.chars().all(|c| c.is_ascii_hexdigit()))
            .ok_or_else(|| "invalid byte array format".to_string())?;
        out.push(u8::from_str_radix(hex, 16).map_err(|_| "invalid byte array format".to_string())?);
    }
    Ok(out)
}

fn is_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// Labels must start and end with an alphanumeric character and may contain
/// hyphens. `*` and `**` are allowed as standalone labels.
pub fn check_domain_pattern(v: &str) -> Result<(), String> {
    let ok = !v.is_empty() && v.split('.').all(|l| l == "*" || l == "**" || is_label(l));
    if ok {
        Ok(())
    } else {
        Err("invalid domain pattern".into())
    }
}

/// Parses `addr/prefix` and returns the network address (host bits masked).
pub fn parse_cidr(v: &str) -> Result<(IpAddr, u8), String> {
    let err = || format!("wrongCIDR '{v}': invalid CIDR address: {v}");
    let (ip, len) = v.split_once('/').ok_or_else(err)?;
    let ip: IpAddr = ip.parse().map_err(|_| err())?;
    if len.is_empty() || !len.chars().all(|c| c.is_ascii_digit()) {
        return Err(err());
    }
    let len: u8 = len.parse().map_err(|_| err())?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(err());
    }
    Ok((mask_ip(ip, len), len))
}

pub fn mask_ip(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if len == 0 {
                0
            } else {
                u32::MAX << (32 - len as u32)
            };
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len as u32)
            };
            IpAddr::V6((bits & mask).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port() {
        assert_eq!(parse_host_port("8.8.8.8:53").unwrap().to_string(), "8.8.8.8:53");
        assert_eq!(parse_host_port("[::1]:1080").unwrap().to_string(), "[::1]:1080");
        assert!(parse_host_port("dns.google:53").is_err());
        assert!(parse_host_port("1.1.1.1").is_err());
        assert!(parse_host_port("1.1.1.1:70000").is_err());
    }

    #[test]
    fn hex_bytes() {
        assert_eq!(
            parse_hex_bytes("0x16, 0x03,0x01").unwrap(),
            vec![0x16, 0x03, 0x01]
        );
        assert_eq!(parse_hex_bytes("  ").unwrap(), Vec::<u8>::new());
        assert!(parse_hex_bytes("16, 03").is_err());
        assert!(parse_hex_bytes("0x1").is_err());
    }

    #[test]
    fn domain_patterns() {
        for ok in [
            "example.com",
            "*.google.com",
            "**.youtube.com",
            "a-b.c",
            "localhost",
        ] {
            assert!(check_domain_pattern(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-a.com", "a-.com", "a..com", "***.com", "a_b.com"] {
            assert!(check_domain_pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cidr() {
        assert_eq!(
            parse_cidr("192.168.1.7/24").unwrap(),
            ("192.168.1.0".parse().unwrap(), 24)
        );
        assert_eq!(
            parse_cidr("2001:db8::1/32").unwrap(),
            ("2001:db8::".parse().unwrap(), 32)
        );
        assert!(parse_cidr("10.0.0.0").is_err());
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("not-a-cidr").is_err());
    }
}
