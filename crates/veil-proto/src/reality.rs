//! REALITY client: a hand-rolled TLS 1.3 client whose ClientHello carries an
//! authenticated session id, and which accepts only the server's REALITY
//! certificate (ed25519 key signed with HMAC-SHA512 over the shared secret).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Buf, BytesMut};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::{Ciphertext, Decapsulate, DecapsulationKey, KeyExport, MlKem768};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{Aead, TAG_LEN};

/// Version reported inside the session id (servers may enforce a minimum).
const CLIENT_VERSION: [u8; 3] = [26, 1, 0];

const CT_CHANGE_CIPHER_SPEC: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPLICATION_DATA: u8 = 23;

const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

const MAX_PLAINTEXT: usize = 16 * 1024;

const GROUP_X25519: u16 = 0x001d;
/// Hybrid post-quantum group; REALITY servers reject hellos without it.
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;

#[derive(Debug, Clone)]
pub struct RealityParams {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
}

impl RealityParams {
    pub fn new(server_name: &str, public_key_b64: &str, short_id_hex: &str) -> io::Result<Self> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("reality: {m}"));
        let pk = URL_SAFE_NO_PAD
            .decode(public_key_b64.trim_end_matches('='))
            .map_err(|_| bad("public key is not base64"))?;
        let public_key: [u8; 32] = pk.try_into().map_err(|_| bad("public key must be 32 bytes"))?;
        if short_id_hex.len() > 16 || !short_id_hex.len().is_multiple_of(2) {
            return Err(bad("short id must be up to 16 hex characters"));
        }
        let mut short_id = [0u8; 8];
        for (i, pair) in short_id_hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).unwrap();
            short_id[i] = u8::from_str_radix(s, 16).map_err(|_| bad("short id is not hex"))?;
        }
        Ok(Self { server_name: server_name.to_string(), public_key, short_id })
    }
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("reality: {}", msg.into()))
}

// ---- cipher suites & key schedule ----------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl Suite {
    fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Suite::Aes128GcmSha256),
            0x1302 => Some(Suite::Aes256GcmSha384),
            0x1303 => Some(Suite::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    fn sha384(self) -> bool {
        self == Suite::Aes256GcmSha384
    }

    fn hash_len(self) -> usize {
        if self.sha384() { 48 } else { 32 }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        if self.sha384() { Sha384::digest(data).to_vec() } else { Sha256::digest(data).to_vec() }
    }

    fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        if self.sha384() {
            Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec()
        } else {
            Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec()
        }
    }

    fn expand_label(self, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
        let full = format!("tls13 {label}");
        let mut info = Vec::with_capacity(4 + full.len() + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        let mut out = vec![0u8; len];
        if self.sha384() {
            Hkdf::<Sha384>::from_prk(secret).unwrap().expand(&info, &mut out).unwrap();
        } else {
            Hkdf::<Sha256>::from_prk(secret).unwrap().expand(&info, &mut out).unwrap();
        }
        out
    }

    fn derive_secret(self, secret: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, &self.hash(transcript), self.hash_len())
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        if self.sha384() {
            let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).unwrap();
            m.update(data);
            m.finalize().into_bytes().to_vec()
        } else {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }

    fn traffic_keys(self, secret: &[u8]) -> RecordKeys {
        let key_len = if self == Suite::Aes128GcmSha256 { 16 } else { 32 };
        let key = self.expand_label(secret, "key", &[], key_len);
        let iv: [u8; 12] = self.expand_label(secret, "iv", &[], 12).try_into().unwrap();
        let aead = match self {
            Suite::Aes128GcmSha256 => Aead::aes128(&key),
            Suite::Aes256GcmSha384 => Aead::aes256(&key),
            Suite::Chacha20Poly1305Sha256 => Aead::chacha(&key),
        };
        RecordKeys { aead, iv, seq: 0 }
    }
}

struct RecordKeys {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKeys {
    fn nonce(&mut self) -> [u8; 12] {
        let mut n = self.iv;
        for (b, s) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *b ^= s;
        }
        self.seq += 1;
        n
    }

    fn seal(&mut self, content_type: u8, data: &[u8], out: &mut BytesMut) {
        let mut body = Vec::with_capacity(data.len() + 1 + TAG_LEN);
        body.extend_from_slice(data);
        body.push(content_type);
        let len = (body.len() + TAG_LEN) as u16;
        let header = [CT_APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
        let nonce = self.nonce();
        self.aead.seal(&nonce, &header, &mut body);
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
    }

    /// Decrypts a record body; returns (inner content type, plaintext).
    fn open(&mut self, header: &[u8; 5], body: Vec<u8>) -> io::Result<(u8, Vec<u8>)> {
        let mut body = body;
        let nonce = self.nonce();
        self.aead.open(&nonce, header, &mut body)?;
        while body.last() == Some(&0) {
            body.pop();
        }
        let ct = body.pop().ok_or_else(|| err("empty inner plaintext"))?;
        Ok((ct, body))
    }
}

// ---- ClientHello ---------------------------------------------------------

fn grease(rng: &mut impl Rng) -> u16 {
    let n = rng.gen_range(0..16u16);
    (n << 12) | 0x0a00 | (n << 4) | 0x0a
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn ext(out: &mut Vec<u8>, ty: u16, body: &[u8]) {
    put_u16(out, ty);
    put_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

fn with_len16(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.len() + 2);
    put_u16(&mut v, body.len() as u16);
    v.extend_from_slice(body);
    v
}

/// Builds a Chrome-like ClientHello handshake message with a zeroed session id.
/// `mlkem_ek` is the ML-KEM-768 encapsulation key, `key_share` the X25519 public key.
fn client_hello(sni: &str, random: &[u8; 32], mlkem_ek: &[u8], key_share: &[u8; 32]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let g_cipher = grease(&mut rng);
    let g_ext_first = grease(&mut rng);
    let mut g_ext_last = grease(&mut rng);
    while g_ext_last == g_ext_first {
        g_ext_last = grease(&mut rng);
    }
    let g_group = grease(&mut rng);
    let g_version = grease(&mut rng);

    let mut exts: Vec<Vec<u8>> = Vec::new();
    let mut push = |ty: u16, body: &[u8]| {
        let mut e = Vec::new();
        ext(&mut e, ty, body);
        exts.push(e);
    };

    let mut sni_list = vec![0u8];
    sni_list.extend_from_slice(&with_len16(sni.as_bytes()));
    push(0x0000, &with_len16(&sni_list));
    push(0x0017, &[]); // extended_master_secret
    push(0xff01, &[0]); // renegotiation_info
    let mut groups = Vec::new();
    for g in [g_group, GROUP_X25519_MLKEM768, GROUP_X25519, 0x0017, 0x0018] {
        put_u16(&mut groups, g);
    }
    push(0x000a, &with_len16(&groups));
    push(0x000b, &[1, 0]); // ec_point_formats: uncompressed
    push(0x0023, &[]); // session_ticket
    push(0x0010, &with_len16(b"\x02h2\x08http/1.1"));
    push(0x0005, &[1, 0, 0, 0, 0]); // status_request
    let mut sigs = Vec::new();
    for s in [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601] {
        put_u16(&mut sigs, s);
    }
    push(0x000d, &with_len16(&sigs));
    push(0x0012, &[]); // signed_certificate_timestamp
    let mut shares = Vec::new();
    put_u16(&mut shares, g_group);
    put_u16(&mut shares, 1);
    shares.push(0);
    put_u16(&mut shares, GROUP_X25519_MLKEM768);
    put_u16(&mut shares, (mlkem_ek.len() + 32) as u16);
    shares.extend_from_slice(mlkem_ek);
    shares.extend_from_slice(key_share);
    put_u16(&mut shares, GROUP_X25519);
    put_u16(&mut shares, 32);
    shares.extend_from_slice(key_share);
    push(0x0033, &with_len16(&shares));
    push(0x002d, &[1, 1]); // psk_key_exchange_modes: psk_dhe_ke
    let mut versions = vec![6u8];
    for v in [g_version, 0x0304, 0x0303] {
        put_u16(&mut versions, v);
    }
    push(0x002b, &versions);
    push(0x001b, &[2, 0, 2]); // compress_certificate: brotli
    push(0x44cd, &with_len16(b"\x02h2")); // application_settings
    // Chrome permutes extension order on every connection.
    exts.shuffle(&mut rng);

    let mut ext_bytes = Vec::new();
    ext(&mut ext_bytes, g_ext_first, &[]);
    for e in exts {
        ext_bytes.extend_from_slice(&e);
    }
    ext(&mut ext_bytes, g_ext_last, &[0]);

    let mut body = Vec::new();
    put_u16(&mut body, 0x0303);
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    let mut suites = Vec::new();
    for s in [g_cipher, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035] {
        put_u16(&mut suites, s);
    }
    body.extend_from_slice(&with_len16(&suites));
    body.extend_from_slice(&[1, 0]); // compression: null

    // BoringSSL pads hellos whose record would be 256..511 bytes long.
    let unpadded = 4 + body.len() + 2 + ext_bytes.len();
    if (0x100..0x200).contains(&unpadded) {
        let pad = (0x200 - unpadded).saturating_sub(4).max(1);
        ext(&mut ext_bytes, 0x0015, &vec![0u8; pad]);
    }
    body.extend_from_slice(&with_len16(&ext_bytes));

    let mut msg = vec![1u8];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// Fills the session id per REALITY and returns the derived auth key.
fn seal_session_id(hello: &mut [u8], secret: &StaticSecret, params: &RealityParams, now: u64) -> io::Result<[u8; 32]> {
    let random: [u8; 32] = hello[6..38].try_into().unwrap();
    let mut sid = [0u8; 32];
    sid[..3].copy_from_slice(&CLIENT_VERSION);
    sid[4..8].copy_from_slice(&(now as u32).to_be_bytes());
    sid[8..16].copy_from_slice(&params.short_id);

    let shared = secret.diffie_hellman(&PublicKey::from(params.public_key));
    let mut auth_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes())
        .expand(b"REALITY", &mut auth_key)
        .unwrap();

    // AAD is the whole ClientHello with the session id still zeroed.
    let mut plaintext = sid[..16].to_vec();
    let nonce: [u8; 12] = random[20..].try_into().unwrap();
    Aead::aes256(&auth_key).seal(&nonce, hello, &mut plaintext);
    hello[39..71].copy_from_slice(&plaintext);
    Ok(auth_key)
}

// ---- certificate checks --------------------------------------------------

/// Reads one DER TLV, returning (tag, contents, rest).
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 3 {
            return None;
        }
        let len = input.get(2..2 + n)?.iter().fold(0usize, |a, b| a << 8 | *b as usize);
        (len, 2 + n)
    };
    let content = input.get(hdr..hdr + len)?;
    Some((tag, content, &input[hdr + len..]))
}

/// Extracts (ed25519 public key, signature value) from an X.509 certificate.
fn cert_key_and_signature(cert: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let (_, cert, _) = der(cert)?;
    let (_, tbs, rest) = der(cert)?;
    let (_, _sig_alg, rest) = der(rest)?;
    let (_, sig, _) = der(rest)?;
    let sig = sig.get(1..)?.to_vec(); // skip "unused bits" byte

    let mut fields = tbs;
    if fields.first() == Some(&0xa0) {
        fields = der(fields)?.2; // explicit version
    }
    for _ in 0..5 {
        fields = der(fields)?.2; // serial, signature, issuer, validity, subject
    }
    let (_, spki, _) = der(fields)?;
    let (_, _alg, rest) = der(spki)?;
    let (_, key, _) = der(rest)?;
    let key: [u8; 32] = key.get(1..)?.try_into().ok()?;
    Some((key, sig))
}

// ---- handshake -----------------------------------------------------------

async fn read_record<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    s.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_PLAINTEXT + 256 {
        return Err(err("record too large"));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await?;
    Ok((header, body))
}

/// Pops a full handshake message (type, whole message bytes) from `buf`.
fn next_handshake(buf: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    let msg: Vec<u8> = buf.drain(..4 + len).collect();
    Some((msg[0], msg))
}

fn parse_server_hello(msg: &[u8]) -> io::Result<(Suite, u16, Vec<u8>)> {
    let mut p = &msg[4..];
    if p.len() < 2 + 32 + 1 {
        return Err(err("short ServerHello"));
    }
    if p[2..34] == HELLO_RETRY_RANDOM {
        return Err(err("server sent HelloRetryRequest"));
    }
    p = &p[34..];
    let sid_len = p[0] as usize;
    p = p.get(1 + sid_len..).ok_or_else(|| err("bad ServerHello"))?;
    let suite_id = u16::from_be_bytes([p[0], p[1]]);
    let suite = Suite::from_id(suite_id).ok_or_else(|| err(format!("unsupported cipher suite {suite_id:#06x}")))?;
    p = &p[3..]; // suite + compression
    let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    let mut exts = p.get(2..2 + ext_len).ok_or_else(|| err("bad ServerHello extensions"))?;
    let mut key = None;
    let mut tls13 = false;
    while exts.len() >= 4 {
        let ty = u16::from_be_bytes([exts[0], exts[1]]);
        let len = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        let body = exts.get(4..4 + len).ok_or_else(|| err("truncated extension"))?;
        match ty {
            0x002b => tls13 = body == [3, 4],
            0x0033 if body.len() >= 4 => {
                let group = u16::from_be_bytes([body[0], body[1]]);
                let expected = match group {
                    GROUP_X25519 => 32,
                    GROUP_X25519_MLKEM768 => MLKEM768_CT_LEN + 32,
                    other => return Err(err(format!("server chose unsupported group {other:#06x}"))),
                };
                if body.len() != 4 + expected {
                    return Err(err("bad key share length"));
                }
                key = Some((group, body[4..].to_vec()));
            }
            _ => {}
        }
        exts = &exts[4 + len..];
    }
    if !tls13 {
        return Err(err("server did not negotiate TLS 1.3"));
    }
    let (group, key) = key.ok_or_else(|| err("missing key share"))?;
    Ok((suite, group, key))
}

const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub async fn connect<S>(mut stream: S, params: &RealityParams) -> io::Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    let mut seed = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut seed);
    let mlkem = DecapsulationKey::<MlKem768>::from_seed(seed.into());
    let mlkem_ek = mlkem.encapsulation_key().to_bytes();
    debug_assert_eq!(mlkem_ek.len(), MLKEM768_EK_LEN);

    let mut hello = client_hello(&params.server_name, &random, &mlkem_ek, public.as_bytes());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let auth_key = seal_session_id(&mut hello, &secret, params, now)?;

    let mut record = vec![CT_HANDSHAKE, 3, 1];
    put_u16(&mut record, hello.len() as u16);
    record.extend_from_slice(&hello);
    stream.write_all(&record).await?;

    let mut transcript = hello;

    // ServerHello (plaintext).
    let mut hs_buf = Vec::new();
    let server_hello = loop {
        if let Some((ty, msg)) = next_handshake(&mut hs_buf) {
            if ty != HS_SERVER_HELLO {
                return Err(err("expected ServerHello"));
            }
            break msg;
        }
        let (header, body) = read_record(&mut stream).await?;
        match header[0] {
            CT_HANDSHAKE => hs_buf.extend_from_slice(&body),
            CT_ALERT => return Err(err(format!("server alert {body:?}"))),
            other => return Err(err(format!("unexpected record type {other}"))),
        }
    };
    let (suite, group, server_key) = parse_server_hello(&server_hello)?;
    transcript.extend_from_slice(&server_hello);

    let x25519 = |pk: &[u8]| -> [u8; 32] {
        let pk: [u8; 32] = pk.try_into().unwrap();
        *secret.diffie_hellman(&PublicKey::from(pk)).as_bytes()
    };
    let shared: Vec<u8> = match group {
        GROUP_X25519_MLKEM768 => {
            let ct = Ciphertext::<MlKem768>::try_from(&server_key[..MLKEM768_CT_LEN])
                .map_err(|_| err("bad ML-KEM ciphertext"))?;
            let mut ss = mlkem.decapsulate(&ct).to_vec();
            ss.extend_from_slice(&x25519(&server_key[MLKEM768_CT_LEN..]));
            ss
        }
        _ => x25519(&server_key).to_vec(),
    };
    let zeros = vec![0u8; suite.hash_len()];
    let early = suite.extract(&zeros, &zeros);
    let derived = suite.derive_secret(&early, "derived", &[]);
    let handshake_secret = suite.extract(&derived, &shared);
    let c_hs = suite.derive_secret(&handshake_secret, "c hs traffic", &transcript);
    let s_hs = suite.derive_secret(&handshake_secret, "s hs traffic", &transcript);
    let mut server_keys = suite.traffic_keys(&s_hs);

    // Encrypted server flight.
    let mut verified_cert: Option<VerifyingKey> = None;
    loop {
        while let Some((ty, msg)) = next_handshake(&mut hs_buf) {
            match ty {
                HS_ENCRYPTED_EXTENSIONS => {}
                HS_CERTIFICATE => {
                    verified_cert = Some(check_certificate(&msg, &auth_key)?);
                }
                HS_CERTIFICATE_VERIFY => {
                    let key = verified_cert.as_ref().ok_or_else(|| err("CertificateVerify before Certificate"))?;
                    check_certificate_verify(&msg, key, &suite.hash(&transcript))?;
                }
                HS_FINISHED => {
                    let finished_key = suite.expand_label(&s_hs, "finished", &[], suite.hash_len());
                    let expected = suite.hmac(&finished_key, &suite.hash(&transcript));
                    if msg[4..] != expected[..] {
                        return Err(err("server Finished mismatch"));
                    }
                    if verified_cert.is_none() {
                        return Err(err("server sent no certificate"));
                    }
                    transcript.extend_from_slice(&msg);
                    return finish(stream, suite, &handshake_secret, &c_hs, transcript, hs_buf).await;
                }
                other => return Err(err(format!("unexpected handshake message {other}"))),
            }
            transcript.extend_from_slice(&msg);
        }
        let (header, body) = read_record(&mut stream).await?;
        match header[0] {
            CT_CHANGE_CIPHER_SPEC => continue,
            CT_APPLICATION_DATA => {
                let (ct, plain) = server_keys.open(&header, body)?;
                match ct {
                    CT_HANDSHAKE => hs_buf.extend_from_slice(&plain),
                    CT_ALERT => return Err(err(format!("server alert {plain:?}"))),
                    other => return Err(err(format!("unexpected inner type {other}"))),
                }
            }
            CT_ALERT => return Err(err(format!("server alert {body:?}"))),
            other => return Err(err(format!("unexpected record type {other}"))),
        }
    }
}

fn check_certificate(msg: &[u8], auth_key: &[u8; 32]) -> io::Result<VerifyingKey> {
    let body = &msg[4..];
    let ctx_len = *body.first().ok_or_else(|| err("bad Certificate"))? as usize;
    let list = body.get(1 + ctx_len + 3..).ok_or_else(|| err("bad Certificate"))?;
    let cert_len = u32::from_be_bytes([0, list[0], list[1], list[2]]) as usize;
    let cert = list.get(3..3 + cert_len).ok_or_else(|| err("bad Certificate"))?;
    let (key, signature) = cert_key_and_signature(cert)
        .ok_or_else(|| err("certificate is not a REALITY certificate (wrong server or public key?)"))?;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).unwrap();
    mac.update(&key);
    if mac.verify_slice(&signature).is_err() {
        return Err(err("certificate verification failed: wrong public key/short id, or the server is not REALITY"));
    }
    VerifyingKey::from_bytes(&key).map_err(|_| err("bad ed25519 key"))
}

fn check_certificate_verify(msg: &[u8], key: &VerifyingKey, transcript_hash: &[u8]) -> io::Result<()> {
    let body = &msg[4..];
    if body.len() < 4 || body[..2] != [0x08, 0x07] {
        return Err(err("CertificateVerify is not ed25519"));
    }
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let sig = Signature::from_slice(body.get(4..4 + sig_len).ok_or_else(|| err("bad CertificateVerify"))?)
        .map_err(|_| err("bad signature"))?;
    let mut signed = vec![0x20u8; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(transcript_hash);
    key.verify(&signed, &sig).map_err(|_| err("CertificateVerify signature invalid"))
}

async fn finish<S>(
    mut stream: S,
    suite: Suite,
    handshake_secret: &[u8],
    c_hs: &[u8],
    transcript: Vec<u8>,
    leftover_handshake: Vec<u8>,
) -> io::Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let zeros = vec![0u8; suite.hash_len()];
    let derived = suite.derive_secret(handshake_secret, "derived", &[]);
    let master = suite.extract(&derived, &zeros);
    let c_ap = suite.derive_secret(&master, "c ap traffic", &transcript);
    let s_ap = suite.derive_secret(&master, "s ap traffic", &transcript);

    let finished_key = suite.expand_label(c_hs, "finished", &[], suite.hash_len());
    let verify = suite.hmac(&finished_key, &suite.hash(&transcript));
    let mut fin = vec![HS_FINISHED];
    fin.extend_from_slice(&(verify.len() as u32).to_be_bytes()[1..]);
    fin.extend_from_slice(&verify);

    let mut out = BytesMut::new();
    out.extend_from_slice(&[CT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
    suite.traffic_keys(c_hs).seal(CT_HANDSHAKE, &fin, &mut out);
    stream.write_all(&out).await?;
    stream.flush().await?;

    if !leftover_handshake.is_empty() {
        tracing::debug!("reality: ignoring {} trailing handshake bytes", leftover_handshake.len());
    }
    Ok(RealityStream {
        inner: stream,
        read_keys: suite.traffic_keys(&s_ap),
        write_keys: suite.traffic_keys(&c_ap),
        rbuf: BytesMut::new(),
        plain: BytesMut::new(),
        pending: BytesMut::new(),
        eof: false,
    })
}

// ---- record layer --------------------------------------------------------

pub struct RealityStream<S> {
    inner: S,
    read_keys: RecordKeys,
    write_keys: RecordKeys,
    /// Raw bytes read from `inner` but not yet decrypted.
    rbuf: BytesMut,
    /// Decrypted application data not yet returned.
    plain: BytesMut,
    /// Encrypted records not yet written.
    pending: BytesMut,
    eof: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> RealityStream<S> {
    /// Encrypts `data` into the outgoing queue without doing any IO.
    pub fn queue(&mut self, data: &[u8]) {
        for chunk in data.chunks(MAX_PLAINTEXT) {
            self.write_keys.seal(CT_APPLICATION_DATA, chunk, &mut self.pending);
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(n);
        }
        Poll::Ready(Ok(()))
    }

    /// Hands over buffered plaintext and undecrypted bytes, for switching to raw IO.
    pub fn take_buffered(&mut self) -> (BytesMut, BytesMut) {
        (std::mem::take(&mut self.plain), std::mem::take(&mut self.rbuf))
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.plain.is_empty() && !self.eof {
            if self.rbuf.len() >= 5 {
                let len = u16::from_be_bytes([self.rbuf[3], self.rbuf[4]]) as usize;
                if self.rbuf.len() >= 5 + len {
                    let header: [u8; 5] = self.rbuf[..5].try_into().unwrap();
                    let body = self.rbuf[5..5 + len].to_vec();
                    self.rbuf.advance(5 + len);
                    match header[0] {
                        CT_APPLICATION_DATA => {
                            let (ct, data) = self.read_keys.open(&header, body)?;
                            match ct {
                                CT_APPLICATION_DATA => self.plain.extend_from_slice(&data),
                                CT_HANDSHAKE => {
                                    // NewSessionTicket; KeyUpdate would need a rekey.
                                    if data.first().is_some_and(|t| *t != HS_NEW_SESSION_TICKET) {
                                        return Poll::Ready(Err(err("unsupported post-handshake message")));
                                    }
                                }
                                CT_ALERT => self.eof = true,
                                _ => return Poll::Ready(Err(err("unexpected inner content type"))),
                            }
                        }
                        CT_CHANGE_CIPHER_SPEC => {}
                        CT_ALERT => self.eof = true,
                        _ => return Poll::Ready(Err(err("unexpected record"))),
                    }
                    continue;
                }
            }
            let mut tmp = [0u8; 32 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                self.eof = true;
            }
            self.rbuf.extend_from_slice(rb.filled());
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_record(cx))?;
        let n = this.plain.len().min(buf.remaining());
        buf.put_slice(&this.plain.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.len() >= 4 * MAX_PLAINTEXT {
            ready!(this.poll_drain(cx))?;
        }
        let n = buf.len().min(MAX_PLAINTEXT);
        this.queue(&buf[..n]);
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params() {
        let p = RealityParams::new("a.com", "IOgFivZsFuwtRLTOWITOD-PNuXxHUnkgzsqdgtfOM4Y", "6ba8").unwrap();
        assert_eq!(p.short_id, [0x6b, 0xa8, 0, 0, 0, 0, 0, 0]);
        assert!(RealityParams::new("a.com", "short", "").is_err());
        assert!(RealityParams::new("a.com", "IOgFivZsFuwtRLTOWITOD-PNuXxHUnkgzsqdgtfOM4Y", "abc").is_err());
    }

    #[test]
    fn hello_layout() {
        let hello = client_hello("example.com", &[7u8; 32], &[1u8; MLKEM768_EK_LEN], &[9u8; 32]);
        assert_eq!(hello[0], 1);
        let len = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize;
        assert_eq!(len + 4, hello.len());
        assert_eq!(&hello[6..38], &[7u8; 32]);
        assert_eq!(hello[38], 32);
    }

    #[test]
    fn tls13_key_schedule_rfc8448() {
        // RFC 8448 "Simple 1-RTT Handshake": early secret from zero PSK.
        let s = Suite::Aes128GcmSha256;
        let zeros = [0u8; 32];
        let early = s.extract(&zeros, &zeros);
        assert_eq!(
            early,
            hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
        );
        let derived = s.derive_secret(&early, "derived", &[]);
        assert_eq!(
            derived,
            hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
