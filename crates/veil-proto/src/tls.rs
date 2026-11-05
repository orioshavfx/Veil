use std::io;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub struct TlsClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

/// A rustls client config; `tls13_only` is required for QUIC.
pub fn client_config(alpn: &[String], insecure: bool, tls13_only: bool) -> io::Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone());
    let builder = if tls13_only {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .map_err(io::Error::other)?;
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(config)
}

/// A rustls client config that trusts exactly the server certificates whose SHA-256 (of the
/// leaf DER) is in `pins` (Hysteria 2 `pinSHA256`). Chain and name checks are replaced by the
/// pin, but the handshake signature is still verified against the pinned certificate.
pub fn pinned_client_config(alpn: &[String], pins: Vec<[u8; 32]>, tls13_only: bool) -> io::Result<ClientConfig> {
    if pins.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no certificate pins"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone());
    let builder = if tls13_only {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .map_err(io::Error::other)?;
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { provider, pins }))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(config)
}

impl TlsClient {
    pub fn new(sni: &str, alpn: &[String], insecure: bool) -> io::Result<Self> {
        let config = client_config(alpn, insecure, false)?;
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Self { connector: TlsConnector::from(Arc::new(config)), server_name })
    }

    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S) -> io::Result<TlsStream<S>> {
        self.connector.connect(self.server_name.clone(), stream).await
    }
}

/// Accepts any certificate (the `allowInsecure=1` link option).
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Accepts only a leaf certificate whose SHA-256 matches one of the pins.
#[derive(Debug)]
struct PinVerifier {
    provider: Arc<CryptoProvider>,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&digest) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server certificate does not match pinSHA256".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn verify(pins: Vec<[u8; 32]>, cert: &[u8]) -> Result<ServerCertVerified, rustls::Error> {
        let v = PinVerifier { provider: Arc::new(rustls::crypto::ring::default_provider()), pins };
        v.verify_server_cert(&CertificateDer::from(cert.to_vec()), &[], &ServerName::try_from("x.example").unwrap(), &[], UnixTime::now())
    }

    #[test]
    fn pin_matches_leaf_digest_only() {
        let cert = b"not really a certificate";
        let good: [u8; 32] = Sha256::digest(cert).into();
        assert!(verify(vec![[0; 32], good], cert).is_ok());
        assert!(verify(vec![[0; 32]], cert).is_err());
        assert!(verify(vec![good], b"another certificate").is_err());
    }
}
