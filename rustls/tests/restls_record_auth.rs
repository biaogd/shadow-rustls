// Integration tests are external consumers; rustls::sync is private.
#![allow(clippy::disallowed_types)]
use std::io::Cursor;
use std::sync::Arc;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

fn exchange(masked: bool, corrupt: bool) -> Result<bool, rustls::Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
    let mut client = ClientConnection::new_with_tls13_record_auth(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
        |_| [7; 32],
        |_| [42; 16],
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut first = true;
    for _ in 0..8 {
        let mut out = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut out).unwrap();
        }
        if !out.is_empty() {
            server.read_tls(&mut Cursor::new(out)).unwrap();
            server.process_new_packets()?;
        }
        let mut out = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut out).unwrap();
        }
        let mut offset = 0;
        while offset < out.len() {
            let length = 5 + usize::from(u16::from_be_bytes([out[offset + 3], out[offset + 4]]));
            if out[offset] == 23 && first {
                first = false;
                if masked {
                    for byte in &mut out[offset + 5..offset + 21] {
                        *byte ^= 42;
                    }
                }
                if corrupt {
                    out[offset + 21] ^= 1;
                }
            }
            // Split all records byte-by-byte to exercise the record deframer.
            for byte in &out[offset..offset + length] {
                client.read_tls(&mut Cursor::new([*byte])).unwrap();
                client.process_new_packets()?;
            }
            offset += length;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(client.tls13_record_authenticated());
        }
    }
    panic!("handshake failed to finish");
}

#[test]
fn authenticated_record_preserves_tls_certificate_verification() {
    assert!(exchange(true, false).unwrap());
}

#[test]
fn normal_tls_fallback_uses_untouched_cipher_and_original_record() {
    assert!(!exchange(false, false).unwrap());
}

#[test]
fn corrupt_record_is_never_authenticated() {
    assert!(exchange(true, true).is_err());
}
