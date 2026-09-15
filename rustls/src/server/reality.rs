//! VLESS REALITY **server** Accept support.
//!
//! Authenticates a ClientHello by decrypting the REALITY session_id (ECDH +
//! HKDF-SHA256 + AES-256-GCM) and mints an Ed25519 self-signed certificate whose
//! trailing 64 bytes are `HMAC-SHA512(auth_key, ed25519_pubkey)`.
//!
//! Destination mirroring / record-length camouflage is **not** implemented here;
//! applications (for example rewrite-transport) should wrap
//! [`RealityServerCertResolver`] or call [`authenticate_reality_client_hello`] /
//! [`mint_reality_certified_key`] from a [`crate::server::ResolvesServerCert`]
//! or `LazyConfigAcceptor` flow.
//!
//! Reference: metacubex/utls `RealityServer` authentication path.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::crypto::CryptoProvider;
use crate::sign::SigningKey;
use crate::server::{ClientHello, ResolvesServerCert};
use crate::sign::CertifiedKey;
use crate::sync::Arc;
use crate::time_provider::{DefaultTimeProvider, TimeProvider};

#[cfg(feature = "std")]
use std::sync::Mutex;

/// Configuration for a REALITY TLS server Accept path.
#[derive(Clone, Debug)]
pub struct RealityServerConfig {
    private_key: [u8; 32],
    short_ids: BTreeSet<[u8; 8]>,
    server_names: BTreeSet<String>,
    max_time_diff: Option<Duration>,
    min_client_ver: Option<[u8; 3]>,
    max_client_ver: Option<[u8; 3]>,
    time_provider: Arc<dyn TimeProvider>,
}

impl RealityServerConfig {
    /// Build a REALITY server config from a 32-byte X25519 private key.
    pub fn new(private_key: [u8; 32]) -> Self {
        Self {
            private_key,
            short_ids: BTreeSet::new(),
            server_names: BTreeSet::new(),
            max_time_diff: None,
            min_client_ver: None,
            max_client_ver: None,
            time_provider: Arc::new(DefaultTimeProvider),
        }
    }

    /// Add an accepted short ID (at most 8 bytes, zero-padded on the right).
    pub fn with_short_id(mut self, short_id: impl AsRef<[u8]>) -> Result<Self, RealityServerError> {
        let bytes = short_id.as_ref();
        if bytes.len() > 8 {
            return Err(RealityServerError::ShortIdTooLong);
        }
        let mut id = [0u8; 8];
        id[..bytes.len()].copy_from_slice(bytes);
        self.short_ids.insert(id);
        Ok(self)
    }

    /// Replace the accepted short ID set.
    pub fn with_short_ids<I, B>(mut self, short_ids: I) -> Result<Self, RealityServerError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        self.short_ids.clear();
        for short_id in short_ids {
            self = self.with_short_id(short_id)?;
        }
        Ok(self)
    }

    /// Add an accepted SNI server name.
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_names.insert(name.into());
        self
    }

    /// Replace the accepted server name set.
    pub fn with_server_names<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.server_names = names.into_iter().map(Into::into).collect();
        self
    }

    /// Set the maximum allowed absolute timestamp skew.
    ///
    /// `None` or zero disables the check (matching Go when `MaxTimeDiff == 0`).
    pub fn with_max_time_diff(mut self, max_time_diff: Option<Duration>) -> Self {
        self.max_time_diff = max_time_diff.filter(|d| *d > Duration::ZERO);
        self
    }

    /// Set optional client version bounds (`None` = unbounded on that side).
    pub fn with_client_ver_range(
        mut self,
        min: Option<[u8; 3]>,
        max: Option<[u8; 3]>,
    ) -> Self {
        self.min_client_ver = min;
        self.max_client_ver = max;
        self
    }

    /// Override the time provider (defaults to wall clock).
    pub fn with_time_provider(mut self, time_provider: Arc<dyn TimeProvider>) -> Self {
        self.time_provider = time_provider;
        self
    }

    /// X25519 private key bytes.
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }
}

/// Errors from REALITY server configuration or authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RealityServerError {
    /// Short ID longer than 8 bytes.
    ShortIdTooLong,
    /// Missing SNI or SNI not in the allow-list.
    ServerNameRejected,
    /// ClientHello lacked a usable X25519 key share.
    MissingX25519KeyShare,
    /// Session ID was not 32 bytes.
    InvalidSessionId,
    /// AES-GCM authentication failed.
    AuthDecryptFailed,
    /// Short ID was not accepted.
    ShortIdRejected,
    /// Client version outside configured range.
    ClientVersionRejected,
    /// Timestamp skew exceeded `max_time_diff`.
    TimestampRejected,
    /// Raw ClientHello bytes were missing or malformed for AAD reconstruction.
    InvalidClientHelloEncoding,
    /// Cryptographic helper failed.
    Crypto(String),
}

impl fmt::Display for RealityServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortIdTooLong => write!(f, "REALITY short_id must be at most 8 bytes"),
            Self::ServerNameRejected => write!(f, "REALITY server name rejected"),
            Self::MissingX25519KeyShare => {
                write!(f, "REALITY ClientHello missing X25519 key share")
            }
            Self::InvalidSessionId => write!(f, "REALITY session_id must be 32 bytes"),
            Self::AuthDecryptFailed => write!(f, "REALITY session_id decryption failed"),
            Self::ShortIdRejected => write!(f, "REALITY short_id rejected"),
            Self::ClientVersionRejected => write!(f, "REALITY client version rejected"),
            Self::TimestampRejected => write!(f, "REALITY timestamp rejected"),
            Self::InvalidClientHelloEncoding => {
                write!(f, "REALITY ClientHello encoding invalid for AAD")
            }
            Self::Crypto(msg) => write!(f, "REALITY crypto error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RealityServerError {}

/// Successful REALITY authentication of a ClientHello.
#[derive(Clone, Debug)]
pub struct RealityAuthResult {
    /// Derived AuthKey used for HMAC certificate minting.
    pub auth_key: [u8; 32],
    /// Client version from the decrypted session_id plaintext.
    pub client_version: [u8; 3],
    /// Client short ID from the decrypted session_id plaintext.
    pub short_id: [u8; 8],
    /// Client Unix timestamp from the decrypted session_id plaintext.
    pub client_time: u32,
}

/// Authenticate a REALITY ClientHello.
///
/// Auth path (matches Go utls / Xray):
/// 1. ECDH(server_private, client_x25519_share)
/// 2. HKDF-SHA256(salt=client_random[:20], info="REALITY") → auth_key
/// 3. AES-256-GCM open of 32-byte session_id with nonce=client_random[20..32]
///    and AAD = raw handshake bytes with session_id zeroed (data starts at offset 39)
pub fn authenticate_reality_client_hello(
    config: &RealityServerConfig,
    client_hello: &ClientHello<'_>,
) -> Result<RealityAuthResult, RealityServerError> {
    let server_name = client_hello
        .server_name()
        .ok_or(RealityServerError::ServerNameRejected)?;
    if !config.server_names.is_empty() && !config.server_names.contains(server_name) {
        return Err(RealityServerError::ServerNameRejected);
    }

    let session_id = client_hello.session_id();
    if session_id.len() != 32 {
        return Err(RealityServerError::InvalidSessionId);
    }

    let peer_pub = client_hello
        .reality_x25519_public_key()
        .ok_or(RealityServerError::MissingX25519KeyShare)?;

    let raw = client_hello
        .raw_handshake_message()
        .ok_or(RealityServerError::InvalidClientHelloEncoding)?;
    let aad = reality_aad_from_raw(raw, session_id)?;

    let auth_shared = crate::client::reality::x25519_ecdh(&config.private_key, &peer_pub)
        .map_err(|e| RealityServerError::Crypto(e.to_string()))?;

    let provider = CryptoProvider::get_default_or_install_from_crate_features();
    let hkdf = crate::client::reality::get_hkdf_sha256_from_config(&provider.cipher_suites)
        .map_err(|e| RealityServerError::Crypto(e.to_string()))?;

    let salt = &client_hello.random()[..20];
    let expander = hkdf.extract_from_secret(Some(salt), &auth_shared);
    let mut auth_key = [0u8; 32];
    expander
        .expand_slice(&[b"REALITY"], &mut auth_key)
        .map_err(|_| RealityServerError::Crypto("HKDF expand failed".into()))?;

    let nonce: &[u8; 12] = client_hello.random()[20..32]
        .try_into()
        .map_err(|_| RealityServerError::Crypto("invalid nonce".into()))?;

    let mut ciphertext = [0u8; 32];
    ciphertext.copy_from_slice(session_id);
    let plaintext =
        crate::client::reality::aes_256_gcm_decrypt(&auth_key, nonce, &aad, &ciphertext)
            .map_err(|_| RealityServerError::AuthDecryptFailed)?;

    let mut client_version = [0u8; 3];
    client_version.copy_from_slice(&plaintext[0..3]);
    let client_time = u32::from_be_bytes(plaintext[4..8].try_into().unwrap());
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plaintext[8..16]);

    if let Some(min) = config.min_client_ver {
        if version_value(client_version) < version_value(min) {
            return Err(RealityServerError::ClientVersionRejected);
        }
    }
    if let Some(max) = config.max_client_ver {
        if version_value(client_version) > version_value(max) {
            return Err(RealityServerError::ClientVersionRejected);
        }
    }

    if !config.short_ids.is_empty() && !config.short_ids.contains(&short_id) {
        return Err(RealityServerError::ShortIdRejected);
    }

    if let Some(max_diff) = config.max_time_diff {
        let now = config
            .time_provider
            .current_time()
            .ok_or_else(|| RealityServerError::Crypto("time provider failed".into()))?
            .as_secs();
        let now_u32 = (now % (1u64 << 32)) as u32;
        let delta = now_u32.abs_diff(client_time) as u64;
        if Duration::from_secs(delta) > max_diff {
            return Err(RealityServerError::TimestampRejected);
        }
    }

    Ok(RealityAuthResult {
        auth_key,
        client_version,
        short_id,
        client_time,
    })
}

/// Mint a REALITY HMAC-Ed25519 [`CertifiedKey`] for an authenticated session.
///
/// Uses [`CertifiedKey::new`] without `keys_match` — the HMAC overwrites the
/// X.509 signature bytes, so SPKI/key consistency checks would fail.
pub fn mint_reality_certified_key(
    auth_key: &[u8; 32],
) -> Result<Arc<CertifiedKey>, RealityServerError> {
    let (pkcs8, public_key) =
        generate_ed25519_pkcs8_and_public().map_err(RealityServerError::Crypto)?;

    let hmac = crate::client::reality::hmac_sha512(auth_key, &public_key);
    let mut cert = REALITY_CERT_TEMPLATE.to_vec();
    cert[REALITY_CERT_PUBKEY_OFFSET..REALITY_CERT_PUBKEY_OFFSET + 32].copy_from_slice(&public_key);
    let sig_offset = cert.len() - 64;
    cert[sig_offset..].copy_from_slice(&hmac);

    let signing_key = load_ed25519_signing_key(&pkcs8).map_err(RealityServerError::Crypto)?;

    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(cert)],
        signing_key,
    )))
}

/// [`ResolvesServerCert`] that authenticates REALITY ClientHellos and mints
/// per-connection HMAC certificates.
///
/// On auth failure returns `None` so the caller can fall back (for example
/// dial the camouflage destination via `LazyConfigAcceptor`).
#[derive(Debug)]
pub struct RealityServerCertResolver {
    config: RealityServerConfig,
    #[cfg(feature = "std")]
    last_auth: Mutex<Option<RealityAuthResult>>,
}

impl RealityServerCertResolver {
    /// Create a resolver from a REALITY server config.
    pub fn new(config: RealityServerConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "std")]
            last_auth: Mutex::new(None),
        }
    }

    /// Last successful authentication metadata (if any).
    #[cfg(feature = "std")]
    pub fn last_auth(&self) -> Option<RealityAuthResult> {
        self.last_auth.lock().ok().and_then(|g| g.clone())
    }
}

impl ResolvesServerCert for RealityServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let auth = authenticate_reality_client_hello(&self.config, &client_hello).ok()?;
        let certified = mint_reality_certified_key(&auth.auth_key).ok()?;
        #[cfg(feature = "std")]
        if let Ok(mut slot) = self.last_auth.lock() {
            *slot = Some(auth);
        }
        Some(certified)
    }
}

fn version_value(v: [u8; 3]) -> u32 {
    ((v[0] as u32) << 16) | ((v[1] as u32) << 8) | (v[2] as u32)
}

fn reality_aad_from_raw(raw: &[u8], session_id: &[u8]) -> Result<Vec<u8>, RealityServerError> {
    // HandshakeType(1) + length(3) + legacy_version(2) + random(32) + session_id_len(1)
    if raw.len() < 39 {
        return Err(RealityServerError::InvalidClientHelloEncoding);
    }
    let sid_len = raw[38] as usize;
    if sid_len != session_id.len() || raw.len() < 39 + sid_len {
        return Err(RealityServerError::InvalidClientHelloEncoding);
    }
    if &raw[39..39 + sid_len] != session_id {
        return Err(RealityServerError::InvalidClientHelloEncoding);
    }
    let mut aad = raw.to_vec();
    aad[39..39 + sid_len].fill(0);
    Ok(aad)
}

fn generate_ed25519_pkcs8_and_public() -> Result<(Vec<u8>, [u8; 32]), String> {
    #[cfg(feature = "aws_lc_rs")]
    {
        use aws_lc_rs::{
            rand::SystemRandom,
            signature::{Ed25519KeyPair, KeyPair},
        };
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| format!("Ed25519 generate_pkcs8 failed: {e}"))?;
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref())
            .map_err(|e| format!("Ed25519 from_pkcs8 failed: {e}"))?;
        let mut public = [0u8; 32];
        public.copy_from_slice(pair.public_key().as_ref());
        return Ok((document.as_ref().to_vec(), public));
    }
    #[cfg(all(not(feature = "aws_lc_rs"), feature = "ring"))]
    {
        use ring::{
            rand::SystemRandom,
            signature::{Ed25519KeyPair, KeyPair},
        };
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "Ed25519 generate_pkcs8 failed".to_string())?;
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref())
            .map_err(|_| "Ed25519 from_pkcs8 failed".to_string())?;
        let mut public = [0u8; 32];
        public.copy_from_slice(pair.public_key().as_ref());
        return Ok((document.as_ref().to_vec(), public));
    }
    #[cfg(all(not(feature = "aws_lc_rs"), not(feature = "ring")))]
    {
        Err("REALITY server requires aws_lc_rs or ring".into())
    }
}

fn load_ed25519_signing_key(pkcs8: &[u8]) -> Result<Arc<dyn SigningKey>, String> {
    let der = PrivatePkcs8KeyDer::from(pkcs8.to_vec());
    #[cfg(feature = "aws_lc_rs")]
    {
        return crate::crypto::aws_lc_rs::sign::any_eddsa_type(&der)
            .map_err(|e| format!("load Ed25519 signing key: {e}"));
    }
    #[cfg(all(not(feature = "aws_lc_rs"), feature = "ring"))]
    {
        return crate::crypto::ring::sign::any_eddsa_type(&der)
            .map_err(|e| format!("load Ed25519 signing key: {e}"));
    }
    #[cfg(all(not(feature = "aws_lc_rs"), not(feature = "ring")))]
    {
        let _ = der;
        Err("REALITY server requires aws_lc_rs or ring".into())
    }
}

/// Zeroed Ed25519 self-signed cert template (175 bytes; pubkey @ 70, signature @ end-64).
const REALITY_CERT_TEMPLATE: &[u8] = &[
    0x30, 0x81, 0xad, 0x30, 0x61, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x30, 0x00, 0x30, 0x20, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33,
    0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
    0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const REALITY_CERT_PUBKEY_OFFSET: usize = 70;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::handshake::KeyShareEntry;
    use crate::NamedGroup;
    use pki_types::{DnsName, UnixTime};

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn mint_cert_passes_client_hmac_shape() {
        let auth_key = [0x42u8; 32];
        let certified = mint_reality_certified_key(&auth_key).expect("mint");
        let cert = certified.cert[0].as_ref();
        assert_eq!(cert.len(), REALITY_CERT_TEMPLATE.len());
        assert!(cert.len() >= 64);
        let pubkey =
            crate::client::reality::extract_ed25519_pubkey_from_reality_cert(cert).expect("pubkey");
        let expected = crate::client::reality::hmac_sha512(&auth_key, &pubkey);
        assert_eq!(&cert[cert.len() - 64..], &expected);
        assert_eq!(&cert[REALITY_CERT_PUBKEY_OFFSET..REALITY_CERT_PUBKEY_OFFSET + 32], &pubkey);
    }

    #[test]
    fn aad_zeroes_session_id() {
        let mut raw = vec![0u8; 80];
        raw[0] = 1; // ClientHello
        raw[38] = 32;
        for i in 0..32 {
            raw[39 + i] = (i as u8) + 1;
        }
        let sid = raw[39..71].to_vec();
        let aad = reality_aad_from_raw(&raw, &sid).unwrap();
        assert!(aad[39..71].iter().all(|b| *b == 0));
        assert_eq!(&aad[..39], &raw[..39]);
        assert_eq!(&aad[71..], &raw[71..]);
    }

    #[test]
    fn cert_template_layout() {
        assert_eq!(REALITY_CERT_TEMPLATE.len(), 175);
        assert_eq!(&REALITY_CERT_TEMPLATE[0..4], &[0x30, 0x81, 0xad, 0x30]);
        assert_eq!(&REALITY_CERT_TEMPLATE[62..67], &[0x06, 0x03, 0x2b, 0x65, 0x70]);
        assert_eq!(&REALITY_CERT_TEMPLATE[67..70], &[0x03, 0x21, 0x00]);
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    fn x25519_public_from_private(private: &[u8; 32]) -> [u8; 32] {
        #[cfg(feature = "aws_lc_rs")]
        {
            use aws_lc_rs::agreement;
            let pk = agreement::PrivateKey::from_private_key(&agreement::X25519, private).unwrap();
            let mut out = [0u8; 32];
            out.copy_from_slice(pk.compute_public_key().unwrap().as_ref());
            out
        }
        #[cfg(all(not(feature = "aws_lc_rs"), feature = "ring"))]
        {
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::from(*private);
            PublicKey::from(&secret).to_bytes()
        }
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn authenticate_roundtrip_with_client_session_id() {
        #[cfg(feature = "aws_lc_rs")]
        let _ = crate::crypto::aws_lc_rs::default_provider().install_default();
        #[cfg(all(not(feature = "aws_lc_rs"), feature = "ring"))]
        let _ = crate::crypto::ring::default_provider().install_default();

        let provider = CryptoProvider::get_default().expect("provider");

        let mut server_private = [0u8; 32];
        provider.secure_random.fill(&mut server_private).unwrap();
        let server_public = x25519_public_from_private(&server_private);

        let short_id = vec![0x12, 0x34, 0x56, 0x78];
        let client_cfg = alloc::sync::Arc::new(
            crate::client::RealityConfig::new(server_public, short_id.clone())
                .unwrap()
                .with_client_version([0, 0, 1]),
        );

        let state =
            crate::client::reality::RealitySessionState::new(client_cfg, provider).unwrap();
        let key_share = state.key_share_entry();

        let mut random = [0u8; 32];
        provider.secure_random.fill(&mut random).unwrap();
        let tls_random = crate::msgs::handshake::Random(random);

        // Build AAD: minimal handshake header + body with zeroed session_id
        let mut aad = vec![0u8; 80];
        aad[0] = 1; // ClientHello
        aad[1..4].copy_from_slice(&76u32.to_be_bytes()[1..]); // length placeholder
        aad[4] = 0x03;
        aad[5] = 0x03;
        aad[6..38].copy_from_slice(&random);
        aad[38] = 32;
        // session_id region already zero

        let hkdf =
            crate::client::reality::get_hkdf_sha256_from_config(&provider.cipher_suites).unwrap();

        #[derive(Debug)]
        struct FixedTime;
        impl TimeProvider for FixedTime {
            fn current_time(&self) -> Option<UnixTime> {
                Some(UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000)))
            }
        }
        let time = FixedTime;
        let session_id = state
            .compute_session_id(&tls_random, &aad, hkdf, &time)
            .unwrap();

        let mut raw = aad.clone();
        raw[39..71].copy_from_slice(&session_id);

        let server_cfg = RealityServerConfig::new(server_private)
            .with_server_name("www.example.com")
            .with_short_id(&short_id)
            .unwrap()
            .with_max_time_diff(Some(Duration::from_secs(60)))
            .with_time_provider(Arc::new(FixedTime));

        let sni = Some(DnsName::try_from("www.example.com").unwrap());
        let shares = [key_share];
        let ch = ClientHello {
            server_name: &sni,
            signature_schemes: &[],
            alpn: None,
            server_cert_types: None,
            client_cert_types: None,
            cipher_suites: &[],
            certificate_authorities: None,
            named_groups: None,
            session_id: &session_id,
            random: &random,
            key_shares: Some(&shares),
            raw_handshake_message: Some(&raw),
        };

        let auth = authenticate_reality_client_hello(&server_cfg, &ch).expect("auth");
        assert_eq!(&auth.short_id[..4], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(auth.client_version, [0, 0, 1]);
        assert_eq!(auth.client_time, 1_700_000_000u32);

        let certified = mint_reality_certified_key(&auth.auth_key).unwrap();
        let cert = certified.cert[0].as_ref();
        let pubkey =
            crate::client::reality::extract_ed25519_pubkey_from_reality_cert(cert).unwrap();
        let expected = crate::client::reality::hmac_sha512(&auth.auth_key, &pubkey);
        assert_eq!(&cert[cert.len() - 64..], &expected);

        // Hybrid share: trailing 32 bytes
        let mut hybrid = vec![0u8; 64];
        hybrid[32..].copy_from_slice(&shares[0].payload.0);
        let hybrid_share = KeyShareEntry::new(NamedGroup::X25519MLKEM768, hybrid);
        let hybrid_shares = [hybrid_share];
        let ch_hybrid = ClientHello {
            server_name: &sni,
            signature_schemes: &[],
            alpn: None,
            server_cert_types: None,
            client_cert_types: None,
            cipher_suites: &[],
            certificate_authorities: None,
            named_groups: None,
            session_id: &session_id,
            random: &random,
            key_shares: Some(&hybrid_shares),
            raw_handshake_message: Some(&raw),
        };
        assert!(authenticate_reality_client_hello(&server_cfg, &ch_hybrid).is_ok());
    }
}
