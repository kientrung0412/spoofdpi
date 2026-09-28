//! Expansion of `file:` entries in rule match lists.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::add_warn_msg;

const FILE_PREFIX: &str = "file:";

/// Expands `file:` entries into the file's lines. Blank lines and lines
/// starting with `#` are skipped. A missing file only emits a warning.
pub fn resolve_entries(entries: &[String], config_dir: Option<&Path>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for e in entries {
        let Some(p) = e.strip_prefix(FILE_PREFIX) else {
            out.push(e.clone());
            continue;
        };
        let path = expand_path(p, config_dir);
        match std::fs::read_to_string(&path) {
            Ok(content) => out.extend(
                content
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from),
            ),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                add_warn_msg(format!(
                    "file {:?} not found, skipping",
                    path.display().to_string()
                ));
            }
            Err(err) => return Err(format!("failed to load {:?}: {err}", path.display().to_string())),
        }
    }
    Ok(out)
}

/// Expands `$VAR`, `${VAR}` and `%VAR%` references and a leading `~`.
/// Relative paths are resolved against `config_dir` when given.
pub fn expand_path(p: &str, config_dir: Option<&Path>) -> PathBuf {
    let expanded = expand_env(p);
    let path = if let Some(rest) = expanded
        .strip_prefix("~/")
        .or_else(|| expanded.strip_prefix("~\\"))
    {
        match home_dir() {
            Some(home) => home.join(rest),
            None => PathBuf::from(&expanded),
        }
    } else {
        PathBuf::from(&expanded)
    };
    match config_dir {
        Some(dir) if path.is_relative() => dir.join(path),
        _ => path,
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                if let Some(end) = chars[i + 2..].iter().position(|&c| c == '}') {
                    let name: String = chars[i + 2..i + 2 + end].iter().collect();
                    out.push_str(&std::env::var(&name).unwrap_or_default());
                    i += end + 3;
                    continue;
                }
            } else {
                let name: String = chars[i + 1..]
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                    .collect();
                if !name.is_empty() {
                    out.push_str(&std::env::var(&name).unwrap_or_default());
                    i += 1 + name.chars().count();
                    continue;
                }
            }
        } else if c == '%' {
            if let Some(end) = chars[i + 1..].iter().position(|&c| c == '%') {
                let name: String = chars[i + 1..i + 1 + end].iter().collect();
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    if let Ok(v) = std::env::var(&name) {
                        out.push_str(&v);
                        i += end + 2;
                        continue;
                    }
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_expansion() {
        std::env::set_var("SPOOFDPI_TEST_DIR", "/opt/lists");
        assert_eq!(expand_env("$SPOOFDPI_TEST_DIR/a.txt"), "/opt/lists/a.txt");
        assert_eq!(expand_env("${SPOOFDPI_TEST_DIR}/a.txt"), "/opt/lists/a.txt");
        assert_eq!(expand_env("%SPOOFDPI_TEST_DIR%/a.txt"), "/opt/lists/a.txt");
        assert_eq!(expand_env("100%"), "100%");
    }

    #[test]
    fn resolve_file_entries() {
        let dir = std::env::temp_dir().join(format!("spoofdpi-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("list.txt"), "# comment\n\na.com\n  b.com  \n").unwrap();
        let entries = vec![
            "x.com".to_string(),
            "file:list.txt".to_string(),
            "file:missing.txt".to_string(),
        ];
        let out = resolve_entries(&entries, Some(&dir)).unwrap();
        assert_eq!(out, vec!["x.com", "a.com", "b.com"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
