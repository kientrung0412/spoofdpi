//! TLS record parsing: just enough to find a ClientHello and its SNI.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub const TLS_MAX_PAYLOAD_LEN: u16 = 16384;
pub const TLS_HEADER_LEN: usize = 5;
pub const TLS_HANDSHAKE: u8 = 0x16;

#[derive(Clone, Debug)]
pub struct TlsMessage {
    kind: &'static str,
    raw: Vec<u8>,
}

impl TlsMessage {
    /// Wraps configured fake bytes; they are sent verbatim.
    pub fn fake(raw: Vec<u8>) -> Self {
        Self { kind: "fake", raw }
    }

    pub fn real(raw: Vec<u8>) -> Self {
        Self { kind: "real", raw }
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn is_client_hello(&self) -> bool {
        self.raw.len() > TLS_HEADER_LEN && self.raw[0] == TLS_HANDSHAKE && self.raw[5] == 0x01
    }

    /// Returns `[start, end)` offsets of the SNI host name inside `raw`.
    pub fn sni_offset(&self) -> Result<(usize, usize), &'static str> {
        sni_offset(&self.raw)
    }

    pub fn sni(&self) -> Option<&str> {
        let (s, e) = self.sni_offset().ok()?;
        std::str::from_utf8(&self.raw[s..e]).ok()
    }
}

fn be16(b: &[u8], at: usize) -> usize {
    ((b[at] as usize) << 8) | b[at + 1] as usize
}

pub fn sni_offset(raw: &[u8]) -> Result<(usize, usize), &'static str> {
    if raw.len() < 43 {
        return Err("packet too short");
    }
    let mut curr = 0;
    if raw[curr] != 0x16 {
        return Err("not a handshake packet");
    }
    curr += 5;
    if raw[curr] != 0x01 {
        return Err("not a client hello");
    }
    curr += 4;
    // Protocol version (2) + random (32).
    curr += 34;
    if curr >= raw.len() {
        return Err("packet too short after random");
    }

    let session_id_len = raw[curr] as usize;
    curr += 1 + session_id_len;
    if curr >= raw.len() {
        return Err("packet too short after session id");
    }

    if curr + 2 > raw.len() {
        return Err("packet too short for cipher suites len");
    }
    let cipher_suites_len = be16(raw, curr);
    curr += 2 + cipher_suites_len;
    if curr >= raw.len() {
        return Err("packet too short after cipher suites");
    }

    let compression_len = raw[curr] as usize;
    curr += 1 + compression_len;
    if curr >= raw.len() {
        return Err("packet too short after compression");
    }

    if curr + 2 > raw.len() {
        return Err("no extensions");
    }
    let extensions_len = be16(raw, curr);
    curr += 2;
    let extensions_end = curr + extensions_len;
    if extensions_end > raw.len() {
        return Err("extensions length overflow");
    }

    while curr < extensions_end {
        if curr + 4 > extensions_end {
            break;
        }
        let ext_type = be16(raw, curr);
        let ext_len = be16(raw, curr + 2);
        curr += 4;
        if curr + ext_len > extensions_end {
            break;
        }
        if ext_type == 0x0000 {
            // list length (2) + name type (1) + name length (2) + host name
            if ext_len < 5 {
                return Err("malformed sni extension");
            }
            let name_len = be16(raw, curr + 3);
            let start = curr + 5;
            let end = start + name_len;
            if end > curr + ext_len {
                return Err("malformed sni length");
            }
            return Ok((start, end));
        }
        curr += ext_len;
    }
    Err("sni not found")
}

/// Reads exactly one TLS record (header + payload).
pub async fn read_tls_message<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<TlsMessage> {
    let mut header = [0u8; TLS_HEADER_LEN];
    r.read_exact(&mut header).await?;
    let payload_len = u16::from_be_bytes([header[3], header[4]]);
    if payload_len > TLS_MAX_PAYLOAD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid TLS header; Type={:x}, ProtoVersion: {:x}, PayloadLen: {:x}",
                header[0],
                u16::from_be_bytes([header[1], header[2]]),
                payload_len
            ),
        ));
    }
    let mut raw = vec![0u8; TLS_HEADER_LEN + payload_len as usize];
    raw[..TLS_HEADER_LEN].copy_from_slice(&header);
    r.read_exact(&mut raw[TLS_HEADER_LEN..]).await?;
    Ok(TlsMessage::real(raw))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Builds a minimal but well-formed ClientHello carrying `host` as SNI.
    pub fn client_hello(host: &str) -> Vec<u8> {
        let mut sni_ext = Vec::new();
        let name = host.as_bytes();
        sni_ext.extend_from_slice(&[0x00, 0x00]); // type: server_name
        let list_len = 3 + name.len();
        sni_ext.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        let alpn = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2'];

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xab; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        let ext_len = alpn.len() + sni_ext.len();
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);
        body.extend_from_slice(&alpn);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extract_sni() {
        let raw = client_hello("www.example.com");
        let msg = TlsMessage::real(raw.clone());
        assert!(msg.is_client_hello());
        let (s, e) = msg.sni_offset().unwrap();
        assert_eq!(&raw[s..e], b"www.example.com");
        assert_eq!(msg.sni(), Some("www.example.com"));
    }

    #[test]
    fn builtin_fake_packet_has_google_sni() {
        let msg = TlsMessage::fake(crate::config::FAKE_CLIENT_HELLO.to_vec());
        assert!(msg.is_client_hello());
        // The built-in packet encodes the name with a trailing NUL byte.
        assert!(msg.sni().unwrap().starts_with("www.google.com"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(sni_offset(&[0u8; 10]).is_err());
        let mut raw = client_hello("a.com");
        raw[0] = 0x17;
        assert_eq!(sni_offset(&raw), Err("not a handshake packet"));
    }

    #[tokio::test]
    async fn read_record() {
        let raw = client_hello("abc.com");
        let mut data = raw.clone();
        data.extend_from_slice(b"trailing");
        let mut cur = std::io::Cursor::new(data);
        let msg = read_tls_message(&mut cur).await.unwrap();
        assert_eq!(msg.raw(), &raw[..]);
    }
}
