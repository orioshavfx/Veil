use sha2::{Digest, Sha224};

use crate::Address;
use crate::stream::HeaderStream;

const CMD_CONNECT: u8 = 1;

/// hex(SHA224(password)) CRLF CMD ADDR CRLF
pub fn request_header(password: &str, dst: &Address) -> Vec<u8> {
    let hash = Sha224::digest(password.as_bytes());
    let mut out = Vec::with_capacity(56 + 2 + 1 + 1 + 255 + 2 + 2);
    for b in hash {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.push(CMD_CONNECT);
    dst.write_socks(&mut out);
    out.extend_from_slice(b"\r\n");
    out
}

pub fn wrap<S>(stream: S, password: &str, dst: &Address) -> HeaderStream<S> {
    HeaderStream::new(stream, request_header(password, dst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        let h = request_header("password", &Address::Domain("a.b".into(), 80));
        assert_eq!(&h[..56], b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01");
        assert_eq!(&h[56..], &[b'\r', b'\n', 1, 3, 3, b'a', b'.', b'b', 0, 80, b'\r', b'\n']);
    }
}
