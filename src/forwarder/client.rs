use actix_http::error::HttpError;
use actix_http::Uri;
use actix_service::Service;
use actix_tls::connect::{ConnectInfo, Connection};
use awc::http::Method;
use awc::{Client, ClientBuilder, ClientRequest, Connector};

use std::convert::TryFrom;
use tokio::net::TcpStream;

#[cfg(any(
    feature = "rustls-0_20",
    feature = "rustls-0_21",
    feature = "tls-rustls-0_22",
    feature = "tls-rustls-0_23"
))]
#[derive(Debug)]
pub struct NoCertificateVerification;

#[cfg(feature = "rustls-0_20")]
impl tls_rustls_0_20::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tls_rustls_0_20::Certificate,
        _intermediates: &[tls_rustls_0_20::Certificate],
        _server_name: &tls_rustls_0_20::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<tls_rustls_0_20::client::ServerCertVerified, tls_rustls_0_20::Error> {
        Ok(tls_rustls_0_20::client::ServerCertVerified::assertion())
    }
}

#[cfg(feature = "rustls-0_21")]
impl tls_rustls_0_21::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tls_rustls_0_21::Certificate,
        _intermediates: &[tls_rustls_0_21::Certificate],
        _server_name: &tls_rustls_0_21::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<tls_rustls_0_21::client::ServerCertVerified, tls_rustls_0_21::Error> {
        Ok(tls_rustls_0_21::client::ServerCertVerified::assertion())
    }
}

#[cfg(feature = "tls-rustls-0_22")]
impl tls_rustls_0_22::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tls_rustls_0_22::pki_types::CertificateDer<'_>,
        _intermediates: &[tls_rustls_0_22::pki_types::CertificateDer<'_>],
        _server_name: &tls_rustls_0_22::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: tls_rustls_0_22::pki_types::UnixTime,
    ) -> Result<tls_rustls_0_22::client::danger::ServerCertVerified, tls_rustls_0_22::Error> {
        Ok(tls_rustls_0_22::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tls_rustls_0_22::pki_types::CertificateDer<'_>,
        _dss: &tls_rustls_0_22::DigitallySignedStruct,
    ) -> Result<tls_rustls_0_22::client::danger::HandshakeSignatureValid, tls_rustls_0_22::Error> {
        Ok(tls_rustls_0_22::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tls_rustls_0_22::pki_types::CertificateDer<'_>,
        _dss: &tls_rustls_0_22::DigitallySignedStruct,
    ) -> Result<tls_rustls_0_22::client::danger::HandshakeSignatureValid, tls_rustls_0_22::Error> {
        Ok(tls_rustls_0_22::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tls_rustls_0_22::SignatureScheme> {
        vec![
            tls_rustls_0_22::SignatureScheme::RSA_PKCS1_SHA1,
            tls_rustls_0_22::SignatureScheme::ECDSA_SHA1_Legacy,
            tls_rustls_0_22::SignatureScheme::RSA_PKCS1_SHA256,
            tls_rustls_0_22::SignatureScheme::ECDSA_NISTP256_SHA256,
            tls_rustls_0_22::SignatureScheme::RSA_PKCS1_SHA384,
            tls_rustls_0_22::SignatureScheme::ECDSA_NISTP384_SHA384,
            tls_rustls_0_22::SignatureScheme::RSA_PKCS1_SHA512,
            tls_rustls_0_22::SignatureScheme::ECDSA_NISTP521_SHA512,
            tls_rustls_0_22::SignatureScheme::RSA_PSS_SHA256,
            tls_rustls_0_22::SignatureScheme::RSA_PSS_SHA384,
            tls_rustls_0_22::SignatureScheme::RSA_PSS_SHA512,
            tls_rustls_0_22::SignatureScheme::ED25519,
            tls_rustls_0_22::SignatureScheme::ED448,
        ]
    }
}

#[cfg(feature = "tls-rustls-0_23")]
impl tls_rustls_0_23::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tls_rustls_0_23::pki_types::CertificateDer<'_>,
        _intermediates: &[tls_rustls_0_23::pki_types::CertificateDer<'_>],
        _server_name: &tls_rustls_0_23::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: tls_rustls_0_23::pki_types::UnixTime,
    ) -> Result<tls_rustls_0_23::client::danger::ServerCertVerified, tls_rustls_0_23::Error> {
        Ok(tls_rustls_0_23::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tls_rustls_0_23::pki_types::CertificateDer<'_>,
        _dss: &tls_rustls_0_23::DigitallySignedStruct,
    ) -> Result<tls_rustls_0_23::client::danger::HandshakeSignatureValid, tls_rustls_0_23::Error> {
        Ok(tls_rustls_0_23::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tls_rustls_0_23::pki_types::CertificateDer<'_>,
        _dss: &tls_rustls_0_23::DigitallySignedStruct,
    ) -> Result<tls_rustls_0_23::client::danger::HandshakeSignatureValid, tls_rustls_0_23::Error> {
        Ok(tls_rustls_0_23::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tls_rustls_0_23::SignatureScheme> {
        vec![
            tls_rustls_0_23::SignatureScheme::RSA_PKCS1_SHA1,
            tls_rustls_0_23::SignatureScheme::ECDSA_SHA1_Legacy,
            tls_rustls_0_23::SignatureScheme::RSA_PKCS1_SHA256,
            tls_rustls_0_23::SignatureScheme::ECDSA_NISTP256_SHA256,
            tls_rustls_0_23::SignatureScheme::RSA_PKCS1_SHA384,
            tls_rustls_0_23::SignatureScheme::ECDSA_NISTP384_SHA384,
            tls_rustls_0_23::SignatureScheme::RSA_PKCS1_SHA512,
            tls_rustls_0_23::SignatureScheme::ECDSA_NISTP521_SHA512,
            tls_rustls_0_23::SignatureScheme::RSA_PSS_SHA256,
            tls_rustls_0_23::SignatureScheme::RSA_PSS_SHA384,
            tls_rustls_0_23::SignatureScheme::RSA_PSS_SHA512,
            tls_rustls_0_23::SignatureScheme::ED25519,
            tls_rustls_0_23::SignatureScheme::ED448,
        ]
    }
}

pub(crate) struct ForwardClient {
    client: Client,
    client_unsafe: Client,
}

impl Default for ForwardClient {
    fn default() -> Self {
        // @TODO protocols are limited to HTTP/1.1 for now, as there is some issues on the HTTP/2 side
        // See https://github.com/actix/actix-web/pull/3516
        let connector_safe = Self::build_connector(vec![b"http/1.1".to_vec()], false);
        let connector_unsafe = Self::build_connector(vec![b"http/1.1".to_vec()], true);

        let client = ClientBuilder::new()
            .no_default_headers()
            .disable_redirects()
            .disable_timeout()
            .connector(connector_safe)
            .finish();

        let client_unsafe = ClientBuilder::new()
            .no_default_headers()
            .disable_redirects()
            .disable_timeout()
            .connector(connector_unsafe)
            .finish();

        Self { client, client_unsafe }
    }
}

impl ForwardClient {
    pub fn request<U>(&self, method: Method, uri: U, allow_invalid_certificate: bool) -> ClientRequest
    where
        Uri: TryFrom<U>,
        <Uri as TryFrom<U>>::Error: Into<HttpError>,
    {
        if allow_invalid_certificate {
            self.client_unsafe.request(method, uri)
        } else {
            self.client.request(method, uri)
        }
    }

    pub fn new_connector(
        protocols: Vec<Vec<u8>>,
        allow_invalid_certificate: bool,
    ) -> Connector<impl Service<ConnectInfo<Uri>, Response = Connection<Uri, TcpStream>, Error = actix_tls::connect::ConnectError> + Clone>
    {
        Self::build_connector(protocols, allow_invalid_certificate)
    }

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "rustls-0_23-webpki-roots", feature = "rustls-0_23-native-roots"))] {
            /// Build TLS connector with Rustls v0.23, based on supplied ALPN protocols.
            ///
            /// Note that if other TLS crate features are enabled, Rustls v0.23 will be used.
            fn build_connector(protocols: Vec<Vec<u8>>, allow_invalid_certificate: bool) -> Connector<impl Service<ConnectInfo<Uri>, Response = Connection<Uri, TcpStream>, Error = actix_tls::connect::ConnectError> + Clone> {
                use actix_tls::connect::rustls_0_23::{self, reexports::ClientConfig};

                let connector = awc::Connector::new();

                cfg_if::cfg_if! {
                    if #[cfg(feature = "rustls-0_23-webpki-roots")] {
                        let certs = rustls_0_23::webpki_roots_cert_store();
                    } else if #[cfg(feature = "rustls-0_23-native-roots")] {
                        let certs = rustls_0_23::native_roots_cert_store().expect("Failed to find native root certificates");
                    }
                }

                let mut config = ClientConfig::builder()
                    .with_root_certificates(certs)
                    .with_no_client_auth();

                config.alpn_protocols = protocols;

                if allow_invalid_certificate {
                    config.dangerous().set_certificate_verifier(std::sync::Arc::new(NoCertificateVerification));
                }

                connector.rustls_0_23(std::sync::Arc::new(config))
            }
        } else if #[cfg(any(feature = "rustls-0_22-webpki-roots", feature = "rustls-0_22-native-roots"))] {
            /// Build TLS connector with Rustls v0.22, based on supplied ALPN protocols.
            fn build_connector(protocols: Vec<Vec<u8>>, allow_invalid_certificate: bool) -> Connector<impl Service<ConnectInfo<Uri>, Response = Connection<Uri, TcpStream>, Error = actix_tls::connect::ConnectError> + Clone> {
                use actix_tls::connect::rustls_0_22::{self, reexports::ClientConfig};

                let connector = Connector::new();

                cfg_if::cfg_if! {
                    if #[cfg(feature = "rustls-0_22-webpki-roots")] {
                        let certs = rustls_0_22::webpki_roots_cert_store();
                    } else if #[cfg(feature = "rustls-0_22-native-roots")] {
                        let certs = rustls_0_22::native_roots_cert_store().expect("Failed to find native root certificates");
                    }
                }

                let mut config = ClientConfig::builder()
                    .with_root_certificates(certs)
                    .with_no_client_auth();

                config.alpn_protocols = protocols;

                if allow_invalid_certificate {
                    config.dangerous().set_certificate_verifier(std::sync::Arc::new(NoCertificateVerification));
                }

                connector.rustls_0_22(std::sync::Arc::new(config))
            }
        } else if #[cfg(feature = "rustls-0_21")] {
            /// Build TLS connector with Rustls v0.21, based on supplied ALPN protocols.
            fn build_connector(protocols: Vec<Vec<u8>>, allow_invalid_certificate: bool) -> Connector<impl Service<ConnectInfo<Uri>, Response = Connection<Uri, TcpStream>, Error = actix_tls::connect::ConnectError> + Clone> {
                use actix_tls::connect::rustls_0_21::{reexports::ClientConfig, webpki_roots_cert_store};

                let connector = Connector::new();

                let mut config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(webpki_roots_cert_store())
                    .with_no_client_auth();

                config.alpn_protocols = protocols;

                if allow_invalid_certificate {
                    config.dangerous().set_certificate_verifier(std::sync::Arc::new(NoCertificateVerification));
                }

                connector.rustls_021(std::sync::Arc::new(config))
            }
        } else if #[cfg(feature = "rustls-0_20")] {
            /// Build TLS connector with Rustls v0.20, based on supplied ALPN protocols.
            fn build_connector(protocols: Vec<Vec<u8>>, allow_invalid_certificate: bool) -> Connector<impl Service<ConnectInfo<Uri>, Response = Connection<Uri, TcpStream>, Error = actix_tls::connect::ConnectError> + Clone> {
                use actix_tls::connect::rustls_0_20::{reexports::ClientConfig, webpki_roots_cert_store};

                let connector = Connector::new();

                let mut config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(webpki_roots_cert_store())
                    .with_no_client_auth();

                config.alpn_protocols = protocols;

                if allow_invalid_certificate {
                    config.dangerous().set_certificate_verifier(std::sync::Arc::new(NoCertificateVerification));
                }

                connector.rustls(std::sync::Arc::new(config))
            }
        } else if #[cfg(feature = "openssl")] {
            /// Build TLS connector with OpenSSL, based on supplied ALPN protocols.
            fn build_connector(protocols: Vec<Vec<u8>>, allow_invalid_certificate: bool) -> Connector<impl Service<ConnectInfo<Uri>, Response = Connection<Uri, TcpStream>, Error = actix_tls::connect::ConnectError> + Clone> {
                use actix_tls::connect::openssl::reexports::{SslConnector, SslMethod};
                use bytes::{BufMut, BytesMut};

                let connector = Connector::new();

                let mut alpn = BytesMut::with_capacity(20);
                for proto in &protocols {
                    alpn.put_u8(proto.len() as u8);
                    alpn.put(proto.as_slice());
                }

                let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
                if let Err(err) = ssl.set_alpn_protos(&alpn) {
                    tracing::error!("Can not set ALPN protocol: {err:?}");
                }

                if allow_invalid_certificate {
                    ssl.set_verify(tls_openssl::ssl::SslVerifyMode::NONE);
                }

                connector.openssl(ssl.build())
            }
        } else {
            /// Provides an empty TLS connector when no TLS feature is enabled, or when only the
            /// `rustls-0_23` crate feature is enabled.
            fn build_connector(_: Vec<Vec<u8>>, _: bool) -> Connector<impl Service<ConnectInfo<Uri>, Response = Connection<Uri, TcpStream>, Error = actix_tls::connect::ConnectError> + Clone> {
                awc::Connector::new()
            }
        }
    }
}
