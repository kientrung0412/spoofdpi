//! Minimal DNS message encoding/decoding for A/AAAA lookups.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

pub const RCODE_SUCCESS: u8 = 0;
pub const RCODE_NAME_ERROR: u8 = 3;

pub fn type_name(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_AAAA => "AAAA".into(),
        other => other.to_string(),
    }
}

/// Builds a recursive query for `name`.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid domain name {name:?}"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

#[derive(Debug, Default)]
pub struct Response {
    pub id: u16,
    pub rcode: u8,
    /// A/AAAA answers with their TTLs.
    pub addrs: Vec<(IpAddr, u32)>,
}

fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        let len = *buf.get(pos).ok_or("truncated name")? as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                return Err("truncated name pointer".into());
            }
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

fn be16(buf: &[u8], pos: usize) -> Result<u16, String> {
    buf.get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| "message too short".to_string())
}

pub fn parse_response(buf: &[u8]) -> Result<Response, String> {
    if buf.len() < 12 {
        return Err("message too short".into());
    }
    let id = be16(buf, 0)?;
    let flags = be16(buf, 2)?;
    let qd = be16(buf, 4)?;
    let an = be16(buf, 6)?;

    let mut resp = Response {
        id,
        rcode: (flags & 0x000f) as u8,
        addrs: Vec::new(),
    };

    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(buf, pos)? + 4;
    }
    for _ in 0..an {
        pos = skip_name(buf, pos)?;
        let rtype = be16(buf, pos)?;
        let class = be16(buf, pos + 2)?;
        let ttl = buf
            .get(pos + 4..pos + 8)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or("message too short")?;
        let rdlen = be16(buf, pos + 8)? as usize;
        pos += 10;
        let rdata = buf.get(pos..pos + rdlen).ok_or("message too short")?;
        pos += rdlen;
        if class != CLASS_IN {
            continue;
        }
        match (rtype, rdlen) {
            (TYPE_A, 4) => resp.addrs.push((
                IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                ttl,
            )),
            (TYPE_AAAA, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                resp.addrs.push((IpAddr::V6(Ipv6Addr::from(a)), ttl));
            }
            _ => {}
        }
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let q = build_query(0x1234, "example.com", TYPE_A).unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
        assert!(build_query(1, "a..b", TYPE_A).is_err());
    }

    #[test]
    fn parse_answers_with_compression() {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        // CNAME (skipped), A, AAAA — all using a pointer to offset 12.
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 93, 184, 216, 34]);
        m.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        m.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let r = parse_response(&m).unwrap();
        assert_eq!(r.id, 0x1234);
        assert_eq!(r.rcode, 0);
        assert_eq!(
            r.addrs,
            vec![
                ("93.184.216.34".parse().unwrap(), 256),
                ("2001:db8::1".parse().unwrap(), 30)
            ]
        );
        assert!(parse_response(&m[..20]).is_err());
    }
}
