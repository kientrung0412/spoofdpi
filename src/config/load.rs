//! Load pipeline: defaults → TOML → CLI → finalize → rules → validate.

use std::path::{Path, PathBuf};

use toml::{Table, Value};

use super::cli::Cli;
use super::fileutil::resolve_entries;
use super::parse::check_uint16;
use super::toml_apply::*;
use super::*;

pub const CONFIG_FILENAME: &str = "spoofdpi.toml";

/// Builds the effective configuration. Returns the config and the path of
/// the TOML file that was used, if any.
pub fn load(cli: &Cli) -> Result<(Config, Option<PathBuf>), String> {
    let mut cfg = Config::default();

    let (config_path, table) = if cli.clean {
        (None, None)
    } else {
        match search_toml_file(cli.config.as_deref())? {
            Some(path) => {
                let table = read_toml(&path)
                    .and_then(|t| apply_config(&mut cfg, &t).map(|_| t))
                    .map_err(|e| format!("error parsing '{}': {e}", path.display()))?;
                (Some(path), Some(table))
            }
            None => (None, None),
        }
    };

    cli.apply(&mut cfg);
    cfg.finalize();

    let raw_rules = table.as_ref().map(rules_from_table).unwrap_or_default();
    let config_dir = config_path.as_deref().and_then(Path::parent);
    cfg.rules = resolve_rules(raw_rules, &cfg.runtime, config_dir)?;

    for (i, rule) in cfg.rules.iter().enumerate() {
        if rule.matcher.is_none() {
            return Err(format!("rules[{i}]: rule must have match attribute"));
        }
    }

    Ok((cfg, config_path))
}

fn read_toml(path: &Path) -> Result<Table, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    toml::from_str::<Table>(&content).map_err(|e| e.to_string().trim().to_string())
}

/// Default config file locations, in lookup order.
pub fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if cfg!(windows) {
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
        {
            paths.push(dir.join(CONFIG_FILENAME));
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            paths.push(PathBuf::from(appdata).join("spoofdpi").join(CONFIG_FILENAME));
        }
    } else {
        paths.push(PathBuf::from("/etc").join(CONFIG_FILENAME));
    }

    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        paths.push(PathBuf::from(xdg).join("spoofdpi").join(CONFIG_FILENAME));
    }
    if let Some(home) = real_home() {
        paths.push(home.join(".config").join("spoofdpi").join(CONFIG_FILENAME));
    }
    paths
}

/// Home directory of the invoking user, looking through `sudo`.
fn real_home() -> Option<PathBuf> {
    #[cfg(unix)]
    if let Ok(user) = std::env::var("SUDO_USER") {
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() >= 6 && f[0] == user {
                    return Some(PathBuf::from(f[5]));
                }
            }
        }
    }
    super::fileutil::home_dir()
}

fn search_toml_file(custom: Option<&Path>) -> Result<Option<PathBuf>, String> {
    if let Some(p) = custom {
        return if p.exists() {
            Ok(Some(p.to_path_buf()))
        } else {
            Err(format!("no such file: {}", p.display()))
        };
    }
    Ok(default_config_paths().into_iter().find(|p| p.is_file()))
}

/// Extracts raw `[[rules]]` and deprecated `[[policy.overrides]]` entries.
fn rules_from_table(m: &Table) -> Vec<Table> {
    let mut rules = Vec::new();
    if let Some(Value::Array(arr)) = m.get("rules") {
        rules.extend(arr.iter().filter_map(|v| v.as_table().cloned()));
    }
    if let Some(Value::Table(policy)) = m.get("policy") {
        if let Some(Value::Array(arr)) = policy.get("overrides") {
            add_warn_msg("'[[policy.overrides]]' is deprecated; rename to '[[rules]]'");
            rules.extend(arr.iter().filter_map(|v| v.as_table().cloned()));
        }
    }
    rules
}

/// Expands `file:` entries of a raw match table in place.
fn expand_file_match_list(m: &mut Table, idx: usize, config_dir: Option<&Path>) -> Result<(), String> {
    let Some(Value::Table(matcher)) = m.get_mut("match") else {
        return Ok(());
    };
    for key in ["domains", "cidrs"] {
        let Some(Value::Array(arr)) = matcher.get(key) else {
            continue;
        };
        let entries: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        let expanded =
            resolve_entries(&entries, config_dir).map_err(|e| format!("rule {idx}: match.{key}: {e}"))?;
        matcher.insert(
            key.to_string(),
            Value::Array(expanded.into_iter().map(Value::String).collect()),
        );
    }
    Ok(())
}

/// Turns raw rule tables into fully populated rules. Each rule's config
/// starts from the finalized base config and is overlaid with the rule's own
/// sections, so sparse rules inherit every unset value.
pub fn resolve_rules(
    raw: Vec<Table>,
    base: &RuntimeConfig,
    config_dir: Option<&Path>,
) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::with_capacity(raw.len());
    for (i, mut item) in raw.into_iter().enumerate() {
        expand_file_match_list(&mut item, i, config_dir)?;

        let mut rule = Rule {
            name: String::new(),
            priority: 0,
            block: false,
            matcher: None,
            config: base.clone(),
        };
        // `skip` is intentionally not inherited: a global skip must not turn
        // every rule into a no-op. Only the rule itself can set it.
        rule.config.https.skip = false;
        rule.config.udp.skip = false;

        if let Some(Value::String(v)) = item.get("name") {
            rule.name = v.clone();
        }
        if let Some(v) = item.get("priority") {
            let n = v
                .as_integer()
                .ok_or_else(|| format!("rule {i}: priority: expected int64"))?;
            rule.priority = check_uint16(n).map_err(|e| format!("rule {i}: priority: {e}"))?;
        }
        if let Some(Value::Boolean(v)) = item.get("block") {
            rule.block = *v;
        }
        if let Some(v) = item.get("match") {
            rule.matcher = Some(parse_match(v).map_err(|e| format!("rule {i}: match: {e}"))?);
        }
        if let Some(v) = item.get("dns") {
            apply_dns(&mut rule.config.dns, v).map_err(|e| format!("rule {i}: dns: {e}"))?;
        }
        if let Some(v) = item.get("https") {
            apply_https(&mut rule.config.https, v).map_err(|e| format!("rule {i}: https: {e}"))?;
        }
        if let Some(v) = item.get("udp") {
            apply_udp(&mut rule.config.udp, v).map_err(|e| format!("rule {i}: udp: {e}"))?;
        }
        if let Some(v) = item.get("connection") {
            apply_conn(&mut rule.config.conn, v).map_err(|e| format!("rule {i}: connection: {e}"))?;
        }
        rules.push(rule);
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Result<Config, String> {
        let table: Table = toml::from_str(src).map_err(|e| e.to_string())?;
        let mut cfg = Config::default();
        apply_config(&mut cfg, &table)?;
        cfg.finalize();
        cfg.rules = resolve_rules(rules_from_table(&table), &cfg.runtime, None)?;
        Ok(cfg)
    }

    #[test]
    fn defaults() {
        let mut cfg = Config::default();
        cfg.finalize();
        assert_eq!(cfg.listen_addr().to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.runtime.https.split_mode, SplitMode::Sni);
        assert_eq!(cfg.runtime.https.chunk_size, 35);
        assert_eq!(cfg.runtime.dns.addr.to_string(), "8.8.8.8:53");
        assert_eq!(cfg.runtime.https.fake_packet.len(), FAKE_CLIENT_HELLO.len());
        assert!(!cfg.needs_packet());
    }

    #[test]
    fn socks5_default_port() {
        let cfg = parse("[app]\nmode = \"socks5\"\n").unwrap();
        assert_eq!(cfg.listen_addr().to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn full_file() {
        let cfg = parse(
            r#"
[app]
log-level = "debug"
listen-addr = "0.0.0.0:9000"
auto-configure-network = true

[connection]
default-fake-ttl = 5
tcp-timeout = 3000

[dns]
mode = "https"
https-url = "https://1.1.1.1/dns-query"
qtype = "all"
cache = true

[https]
split-mode = "chunk"
chunk-size = 4
disorder = true
fake-count = 3
fake-packet = [0x16, 0x03, 0x01]

[udp]
fake-count = 2

[[rules]]
name = "youtube"
priority = 10
match = { domains = ["**.youtube.com"] }
https = { split-mode = "custom", custom-segments = [ { from = "sni", at = 2, lazy = true } ] }

[[rules]]
name = "blocked"
priority = 5
block = true
match = { cidrs = ["10.0.0.0/8"] }
"#,
        )
        .unwrap();

        assert_eq!(cfg.app.log_level, crate::logging::Level::Debug);
        assert_eq!(cfg.listen_addr().to_string(), "0.0.0.0:9000");
        assert!(cfg.app.auto_configure_network);
        assert_eq!(cfg.runtime.conn.default_fake_ttl, 5);
        assert_eq!(cfg.runtime.conn.tcp_timeout.as_millis(), 3000);
        assert_eq!(cfg.runtime.dns.mode, DnsMode::Https);
        assert_eq!(cfg.runtime.dns.qtype, DnsQueryType::All);
        assert_eq!(cfg.runtime.https.split_mode, SplitMode::Chunk);
        assert_eq!(*cfg.runtime.https.fake_packet, vec![0x16, 0x03, 0x01]);
        assert!(cfg.needs_packet_tcp() && cfg.needs_packet_udp());

        let yt = &cfg.rules[0];
        assert_eq!(yt.name, "youtube");
        assert_eq!(yt.config.https.split_mode, SplitMode::Custom);
        assert_eq!(yt.config.https.custom_segments.len(), 1);
        // Inherited from the base config.
        assert_eq!(yt.config.https.fake_count, 3);
        assert_eq!(yt.config.dns.mode, DnsMode::Https);

        assert!(cfg.rules[1].block);
    }

    #[test]
    fn skip_not_inherited() {
        let cfg = parse("[https]\nskip = true\n[[rules]]\nmatch = { domains = [\"a.com\"] }\n").unwrap();
        assert!(cfg.runtime.https.skip);
        assert!(!cfg.rules[0].config.https.skip);
    }

    #[test]
    fn errors() {
        assert!(parse("[app]\nmode = \"bogus\"\n").unwrap_err().contains("mode"));
        assert!(parse("[https]\nsplit-mode = \"custom\"\n").is_err());
        assert!(parse("[https]\nchunk-size = 0\n").is_err());
        assert!(parse("[dns]\naddr = \"dns.google:53\"\n").is_err());
        assert!(parse("[[rules]]\nmatch = { domains = [\"-bad.com\"] }\n").is_err());
        assert!(parse("[[rules]]\nmatch = { }\n").is_err());
        assert!(parse("[app]\nno-tui = \"yes\"\n")
            .unwrap_err()
            .contains("expected bool"));
    }

    #[test]
    fn deprecated_policy_overrides() {
        let cfg = parse("[[policy.overrides]]\nmatch = { domains = [\"a.com\"] }\n").unwrap();
        assert_eq!(cfg.rules.len(), 1);
    }
}
