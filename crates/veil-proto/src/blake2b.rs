//! BLAKE2b (RFC 7693), unkeyed, written out because the workspace has no `blake2` crate.
//! Used by Hysteria 2 Salamander obfuscation (BLAKE2b-256).

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for r in 0..12 {
        let s = &SIGMA[r % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Unkeyed BLAKE2b with a digest of `out_len` bytes (1..=64).
pub fn blake2b(data: &[u8], out_len: usize) -> Vec<u8> {
    assert!((1..=64).contains(&out_len), "BLAKE2b digest length must be 1..=64");
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ out_len as u64; // fanout 1, depth 1, key length 0
    if data.is_empty() {
        compress(&mut h, &[0u8; 128], 0, true);
    } else {
        let mut t = 0u128;
        let mut chunks = data.chunks(128).peekable();
        while let Some(c) = chunks.next() {
            let mut block = [0u8; 128];
            block[..c.len()].copy_from_slice(c);
            t += c.len() as u128;
            compress(&mut h, &block, t, chunks.peek().is_none());
        }
    }
    let mut out = Vec::with_capacity(64);
    for w in h {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.truncate(out_len);
    out
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    blake2b(data, 32).try_into().expect("32-byte digest")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rfc7693_abc_512() {
        assert_eq!(
            hex(&blake2b(b"abc", 64)),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn empty_512() {
        assert_eq!(
            hex(&blake2b(b"", 64)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    #[test]
    fn abc_256() {
        assert_eq!(hex(&blake2b_256(b"abc")), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    }

    #[test]
    fn block_boundaries_are_stable() {
        for n in [1usize, 127, 128, 129, 255, 256, 257, 1000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let a = blake2b_256(&data);
            assert_eq!(a, blake2b_256(&data), "len {n}");
            let mut other = data.clone();
            *other.last_mut().unwrap() ^= 1;
            assert_ne!(a, blake2b_256(&other), "len {n}");
        }
        // Different lengths must not collide on zero padding.
        assert_ne!(blake2b_256(&[0u8; 128]), blake2b_256(&[0u8; 129]));
        assert_ne!(blake2b_256(&[0u8; 127]), blake2b_256(&[0u8; 128]));
        assert_eq!(blake2b(b"abc", 32).len(), 32);
    }
}
