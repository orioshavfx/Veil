//! Small AEAD wrapper shared by VMess and the REALITY TLS client.

use std::io;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;

pub const TAG_LEN: usize = 16;

pub enum Aead {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl Aead {
    pub fn aes128(key: &[u8]) -> Self {
        Aead::Aes128Gcm(Box::new(Aes128Gcm::new_from_slice(key).expect("16-byte key")))
    }
    pub fn aes256(key: &[u8]) -> Self {
        Aead::Aes256Gcm(Box::new(Aes256Gcm::new_from_slice(key).expect("32-byte key")))
    }
    pub fn chacha(key: &[u8]) -> Self {
        Aead::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new_from_slice(key).expect("32-byte key")))
    }

    /// Encrypts `buf` in place and appends the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>) {
        let n = Nonce::from_slice(nonce);
        match self {
            Aead::Aes128Gcm(c) => c.encrypt_in_place(n, aad, buf),
            Aead::Aes256Gcm(c) => c.encrypt_in_place(n, aad, buf),
            Aead::ChaCha20Poly1305(c) => c.encrypt_in_place(n, aad, buf),
        }
        .expect("encryption cannot fail with Vec buffer");
    }

    /// Decrypts `buf` (ciphertext + tag) in place, leaving the plaintext.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        let n = Nonce::from_slice(nonce);
        match self {
            Aead::Aes128Gcm(c) => c.decrypt_in_place(n, aad, buf),
            Aead::Aes256Gcm(c) => c.decrypt_in_place(n, aad, buf),
            Aead::ChaCha20Poly1305(c) => c.decrypt_in_place(n, aad, buf),
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD authentication failed"))
    }
}
