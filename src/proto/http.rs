//! HTTP/1.x proxy request parsing.

use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

const MAX_HEAD_LEN: usize = 64 * 1024;

const VALID_METHODS: &[&str] = &[
    "DELETE",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "COPY",
    "LOCK",
    "MKCOL",
    "MOVE",
    "PROPFIND",
    "PROPPATCH",
    "SEARCH",
    "UNLOCK",
    "BIND",
    "REBIND",
    "UNBIND",
    "ACL",
    "REPORT",
    "MKACTIVITY",
    "CHECKOUT",
    "MERGE",
    "M-SEARCH",
    "NOTIFY",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "PATCH",
    "PURGE",
    "MKCALENDAR",
    "LINK",
    "UNLINK",
];

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    /// `host[:port]` from the request target or the Host header.
    pub host: String,
}

impl HttpRequest {
    pub fn is_valid_method(&self) -> bool {
        VALID_METHODS.contains(&self.method.as_str())
    }

    pub fn is_connect(&self) -> bool {
        self.method == "CONNECT"
    }

    /// Host without the port (and without IPv6 brackets).
    pub fn extract_host(&self) -> String {
        match split_host_port(&self.host) {
            Some((h, _)) => h.to_string(),
            None => self
                .host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
        }
    }

    pub fn extract_port(&self) -> Result<u16, String> {
        match split_host_port(&self.host) {
            Some((_, p)) => p.parse::<u16>().map_err(|e| e.to_string()),
            None => Ok(if self.is_connect() { 443 } else { 80 }),
        }
    }

    /// Serializes the request head for the origin server: origin-form
    /// target, proxy-only headers dropped.
    pub fn to_origin_head(&self) -> Vec<u8> {
        let mut target = self.target.as_str();
        if let Some(rest) = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"))
        {
            target = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
        }
        let mut out = format!("{} {} {}\r\n", self.method, target, self.version);
        let mut has_host = false;
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case("proxy-connection") || k.eq_ignore_ascii_case("proxy-authorization") {
                continue;
            }
            if k.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        if !has_host {
            out.push_str(&format!("Host: {}\r\n", self.host));
        }
        out.push_str("\r\n");
        out.into_bytes()
    }
}

/// Splits `host:port`, handling `[v6]:port`. Returns `None` without a port.
pub fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let port = rest[end + 1..].strip_prefix(':')?;
        return Some((&rest[..end], port));
    }
    let (h, p) = s.rsplit_once(':')?;
    if h.contains(':') {
        return None; // bare IPv6 without brackets
    }
    Some((h, p))
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Reads and parses a request head. Returns `UnexpectedEof` when the peer
/// closes before sending anything.
pub async fn read_request<R: AsyncBufRead + Unpin>(r: &mut R) -> io::Result<HttpRequest> {
    let mut total = 0usize;
    let mut line = Vec::new();

    let mut next_line = async |line: &mut Vec<u8>, total: &mut usize| -> io::Result<String> {
        line.clear();
        let n = r.read_until(b'\n', line).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        *total += n;
        if *total > MAX_HEAD_LEN {
            return Err(bad("request header too large"));
        }
        let s = String::from_utf8_lossy(line);
        Ok(s.trim_end_matches(['\r', '\n']).to_string())
    };

    let request_line = next_line(&mut line, &mut total).await?;
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) if !m.is_empty() && !t.is_empty() && v.starts_with("HTTP/") => {
            (m.to_string(), t.to_string(), v.to_string())
        }
        _ => return Err(bad(format!("malformed HTTP request {request_line:?}"))),
    };

    let mut headers = Vec::new();
    loop {
        let l = next_line(&mut line, &mut total).await?;
        if l.is_empty() {
            break;
        }
        let (k, v) = l
            .split_once(':')
            .ok_or_else(|| bad(format!("malformed MIME header line: {l}")))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }

    let header_host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let host = if method == "CONNECT" {
        target.clone()
    } else if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        if authority.is_empty() {
            header_host
        } else {
            authority.to_string()
        }
    } else {
        header_host
    };

    if host.is_empty() {
        return Err(bad("missing host"));
    }

    Ok(HttpRequest {
        method,
        target,
        version,
        headers,
        host,
    })
}

pub const CONNECTION_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
pub const BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
pub const FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
pub const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
pub const NOT_IMPLEMENTED: &[u8] = b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n";

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    async fn parse(s: &str) -> io::Result<HttpRequest> {
        let mut r = BufReader::new(s.as_bytes());
        read_request(&mut r).await
    }

    #[tokio::test]
    async fn connect() {
        let req = parse("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        assert!(req.is_connect());
        assert_eq!(req.extract_host(), "example.com");
        assert_eq!(req.extract_port().unwrap(), 443);
    }

    #[tokio::test]
    async fn absolute_form() {
        let req = parse(
            "GET http://example.com/a/b?c=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(req.extract_host(), "example.com");
        assert_eq!(req.extract_port().unwrap(), 80);
        let head = String::from_utf8(req.to_origin_head()).unwrap();
        assert_eq!(head, "GET /a/b?c=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[tokio::test]
    async fn ipv6_host() {
        let req = parse("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(req.extract_host(), "2001:db8::1");
        assert_eq!(req.extract_port().unwrap(), 8443);
    }

    #[tokio::test]
    async fn malformed() {
        assert!(parse("garbage\r\n\r\n").await.is_err());
        assert_eq!(parse("").await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let req = parse("FOO http://a.com/ HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(!req.is_valid_method());
    }
}
