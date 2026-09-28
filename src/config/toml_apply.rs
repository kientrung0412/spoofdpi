//! Overlays TOML tables onto already-populated option structs. Keys that are
//! absent leave the existing value untouched, which is what lets rules
//! inherit everything they do not override.

use std::sync::Arc;
use std::time::Duration;

use toml::{Table, Value};

use super::parse::*;
use super::*;

type Res<T> = Result<T, String>;

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "string",
        Value::Integer(_) => "int64",
        Value::Float(_) => "float64",
        Value::Boolean(_) => "bool",
        Value::Datetime(_) => "datetime",
        Value::Array(_) => "array",
        Value::Table(_) => "table",
    }
}

fn field<T>(key: &str, r: Res<T>) -> Res<T> {
    r.map_err(|e| format!("field {key:?}: {e}"))
}

fn get_bool(m: &Table, key: &str) -> Res<Option<bool>> {
    match m.get(key) {
        None => Ok(None),
        Some(Value::Boolean(b)) => Ok(Some(*b)),
        Some(v) => field(key, Err(format!("expected bool, got {}", type_name(v)))),
    }
}

fn get_int(m: &Table, key: &str) -> Res<Option<i64>> {
    match m.get(key) {
        None => Ok(None),
        Some(Value::Integer(i)) => Ok(Some(*i)),
        Some(v) => field(key, Err(format!("expected int64, got {}", type_name(v)))),
    }
}

fn get_str<'a>(m: &'a Table, key: &str) -> Res<Option<&'a str>> {
    match m.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(v) => field(key, Err(format!("expected string, got {}", type_name(v)))),
    }
}

fn get_bytes(m: &Table, key: &str) -> Res<Option<Vec<u8>>> {
    let Some(v) = m.get(key) else { return Ok(None) };
    let Value::Array(arr) = v else {
        return field(key, Err(format!("expected list, got {}", type_name(v))));
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        match item {
            Value::Integer(n) if (0..=255).contains(n) => out.push(*n as u8),
            Value::Integer(n) => {
                return Err(format!("field {key:?}[{i}]: value {n} out of byte range (0-255)"))
            }
            other => {
                return Err(format!(
                    "field {key:?}[{i}]: expected integer for byte, got {}",
                    type_name(other)
                ))
            }
        }
    }
    Ok(Some(out))
}

pub fn get_str_list(m: &Table, key: &str) -> Res<Option<Vec<String>>> {
    let Some(v) = m.get(key) else { return Ok(None) };
    let Value::Array(arr) = v else {
        return field(key, Err(format!("expected list, got {}", type_name(v))));
    };
    arr.iter()
        .enumerate()
        .map(|(i, item)| match item {
            Value::String(s) => Ok(s.clone()),
            other => Err(format!(
                "field {key:?}[{i}]: expected string, got {}",
                type_name(other)
            )),
        })
        .collect::<Res<Vec<_>>>()
        .map(Some)
}

fn as_table<'a>(v: &'a Value, err: &str) -> Res<&'a Table> {
    v.as_table().ok_or_else(|| err.to_string())
}

pub fn apply_config(cfg: &mut Config, m: &Table) -> Res<()> {
    if let Some(v) = m.get("app") {
        apply_app(&mut cfg.app, v)?;
    }
    if let Some(v) = m.get("connection") {
        apply_conn(&mut cfg.runtime.conn, v)?;
    }
    if let Some(v) = m.get("dns") {
        apply_dns(&mut cfg.runtime.dns, v)?;
    }
    if let Some(v) = m.get("https") {
        apply_https(&mut cfg.runtime.https, v)?;
    }
    if let Some(v) = m.get("udp") {
        apply_udp(&mut cfg.runtime.udp, v)?;
    }
    if let Some(Value::Table(policy)) = m.get("policy") {
        if policy.contains_key("template") {
            add_warn_msg("'policy.template' is deprecated and ignored");
        }
    }
    Ok(())
}

pub fn apply_app(o: &mut AppOptions, v: &Value) -> Res<()> {
    let m = as_table(v, "non-table type general config")?;
    if let Some(b) = get_bool(m, "no-tui")? {
        o.no_tui = b;
    }
    if let Some(b) = get_bool(m, "silent")? {
        o.silent = b;
    }
    if let Some(b) = get_bool(m, "auto-configure-network")? {
        o.auto_configure_network = b;
    }
    if let Some(s) = get_str(m, "log-level")? {
        field("log-level", check_one_of(s, crate::logging::LEVEL_VALUES))?;
        o.log_level = crate::logging::Level::parse(s).unwrap();
    }
    if let Some(s) = get_str(m, "mode")? {
        field("mode", check_one_of(s, APP_MODE_VALUES))?;
        o.mode = AppMode::parse(s).unwrap();
    }
    if let Some(s) = get_str(m, "listen-addr")? {
        o.listen_addr = Some(field("listen-addr", parse_host_port(s))?);
    }
    if let Some(i) = get_int(m, "freebsd-fib")? {
        o.freebsd_fib = field("freebsd-fib", check_freebsd_fib(i))?;
    }
    Ok(())
}

pub fn apply_conn(o: &mut ConnOptions, v: &Value) -> Res<()> {
    let m = as_table(v, "non-table type connection config")?;
    if let Some(i) = get_int(m, "default-fake-ttl")? {
        o.default_fake_ttl = field("default-fake-ttl", check_uint8_non_zero(i))?;
    }
    let ms = |key: &str| -> Res<Option<Duration>> {
        match get_int(m, key)? {
            Some(i) => Ok(Some(Duration::from_millis(field(key, check_uint16(i))? as u64))),
            None => Ok(None),
        }
    };
    if let Some(d) = ms("dns-timeout")? {
        o.dns_timeout = d;
    }
    if let Some(d) = ms("tcp-timeout")? {
        o.tcp_timeout = d;
    }
    if let Some(d) = ms("udp-idle-timeout")? {
        o.udp_idle_timeout = d;
    }
    Ok(())
}

pub fn apply_dns(o: &mut DnsOptions, v: &Value) -> Res<()> {
    let m = as_table(v, "'dns' must be table type")?;
    if let Some(s) = get_str(m, "mode")? {
        field("mode", check_one_of(s, DNS_MODE_VALUES))?;
        o.mode = DnsMode::parse(s).unwrap();
    }
    if let Some(s) = get_str(m, "addr")? {
        o.addr = field("addr", parse_host_port(s))?;
    }
    if let Some(s) = get_str(m, "https-url")? {
        field("https-url", check_https_endpoint(s))?;
        o.https_url = s.to_string();
    }
    if let Some(s) = get_str(m, "qtype")? {
        field("qtype", check_one_of(s, DNS_QUERY_VALUES))?;
        o.qtype = DnsQueryType::parse(s).unwrap();
    }
    if let Some(b) = get_bool(m, "cache")? {
        o.cache = b;
    }
    Ok(())
}

fn parse_segment(v: &Value) -> Res<SegmentPlan> {
    let m = as_table(v, "segment must be table type")?;
    let from = get_str(m, "from")?.ok_or("field 'from' is required")?;
    field("from", check_one_of(from, SEGMENT_FROM_VALUES))?;
    let at = get_int(m, "at")?.ok_or("field 'at' is required")?;
    Ok(SegmentPlan {
        from: SegmentFrom::parse(from).unwrap(),
        at,
        lazy: get_bool(m, "lazy")?.unwrap_or(false),
        noise: get_int(m, "noise")?.unwrap_or(0),
    })
}

pub fn apply_https(o: &mut HttpsOptions, v: &Value) -> Res<()> {
    let m = as_table(v, "'https' must be table type")?;
    if let Some(b) = get_bool(m, "disorder")? {
        o.disorder = b;
    }
    if let Some(i) = get_int(m, "fake-count")? {
        o.fake_count = field("fake-count", check_uint8(i))?;
    }
    if let Some(p) = get_bytes(m, "fake-packet")? {
        o.fake_packet = Arc::new(p);
    }
    if let Some(s) = get_str(m, "split-mode")? {
        field("split-mode", check_one_of(s, SPLIT_MODE_VALUES))?;
        o.split_mode = SplitMode::parse(s).unwrap();
    }
    if let Some(i) = get_int(m, "chunk-size")? {
        o.chunk_size = field("chunk-size", check_uint8_non_zero(i))?;
    }
    if let Some(b) = get_bool(m, "skip")? {
        o.skip = b;
    }
    if let Some(v) = m.get("custom-segments") {
        let Value::Array(items) = v else {
            return Err("field 'custom-segments' is not a list".into());
        };
        o.custom_segments = items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                parse_segment(item).map_err(|e| format!("failed to decode 'custom-segments' item [{i}]: {e}"))
            })
            .collect::<Res<Vec<_>>>()?;
    }
    if o.split_mode == SplitMode::Custom && o.custom_segments.is_empty() {
        return Err("custom-segments must be provided when split-mode is 'custom'".into());
    }
    Ok(())
}

pub fn apply_udp(o: &mut UdpOptions, v: &Value) -> Res<()> {
    let m = as_table(v, "'udp' must be table type")?;
    if let Some(b) = get_bool(m, "skip")? {
        o.skip = b;
    }
    if let Some(i) = get_int(m, "fake-count")? {
        o.fake_count = field("fake-count", check_uint8(i))?;
    }
    if let Some(p) = get_bytes(m, "fake-packet")? {
        o.fake_packet = Arc::new(p);
    }
    Ok(())
}

pub fn parse_match(v: &Value) -> Res<MatchAttrs> {
    let m = as_table(v, "'match' must be table type")?;
    let mut attrs = MatchAttrs::default();
    if let Some(domains) = get_str_list(m, "domains")? {
        for d in &domains {
            check_domain_pattern(d).map_err(|e| format!("invalid domain {d:?}: {e}"))?;
        }
        attrs.domains = domains;
    }
    if let Some(cidrs) = get_str_list(m, "cidrs")? {
        for c in &cidrs {
            parse_cidr(c).map_err(|e| format!("invalid cidr {c:?}: {e}"))?;
        }
        attrs.cidrs = cidrs;
    }
    if attrs.domains.is_empty() && attrs.cidrs.is_empty() {
        return Err("match must have at least one 'domains' or 'cidrs' entry".into());
    }
    Ok(attrs)
}
