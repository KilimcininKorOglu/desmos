//! End-to-end Task 34 mTLS authenticator exercise.
//!
//! Builds fixture certificates in-memory using `ring` to do
//! the actual Ed25519 signing, then drives
//! [`MtlsAuthenticator::authenticate`] across every scenario
//! the `[server.auth] method = "mtls"` config has to handle:
//!
//! 1. a leaf signed by the trusted CA, presented with a valid
//!    transcript signature → accepted,
//! 2. a leaf signed by the trusted CA but with an expired
//!    validity window → rejected,
//! 3. a leaf signed by the trusted CA whose serial is on the
//!    CRL → rejected,
//! 4. a leaf signed by a *different* CA → rejected,
//! 5. a valid leaf but with a transcript signature computed
//!    over the wrong handshake hash → rejected,
//! 6. a truncated credential blob → rejected.
//!
//! No disk fixtures — every certificate is built on the fly
//! from a fresh keypair so the test is self-contained and
//! reproducible across machines.

use desmos_core::auth::{
    mtls::{MtlsAuthenticator, MtlsConfig},
    AuthContext, AuthError, Authenticator,
};
use desmos_proto::crypto::x25519::PublicKey;

use ring::signature::{Ed25519KeyPair, KeyPair};

// ---------------------------------------------------------------------------
// Minimal DER builder
// ---------------------------------------------------------------------------

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0_EXPLICIT: u8 = 0xA0;

const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70]; // 1.3.101.112
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_length(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        panic!("test helper length overflow");
    }
}

fn der_integer(value: u64) -> Vec<u8> {
    let mut body = value.to_be_bytes().to_vec();
    while body.len() > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
        body.remove(0);
    }
    if body[0] & 0x80 != 0 {
        body.insert(0, 0x00);
    }
    der_tlv(TAG_INTEGER, &body)
}

fn der_alg_id_ed25519() -> Vec<u8> {
    der_tlv(TAG_SEQUENCE, &der_tlv(TAG_OID, OID_ED25519))
}

fn der_utc_time(value: &[u8]) -> Vec<u8> {
    der_tlv(TAG_UTC_TIME, value)
}

fn der_common_name(cn: &str) -> Vec<u8> {
    let cn_value = der_tlv(TAG_UTF8_STRING, cn.as_bytes());
    let mut atv = der_tlv(TAG_OID, OID_COMMON_NAME);
    atv.extend_from_slice(&cn_value);
    let atv_seq = der_tlv(TAG_SEQUENCE, &atv);
    let rdn = der_tlv(TAG_SET, &atv_seq);
    der_tlv(TAG_SEQUENCE, &rdn)
}

fn der_spki_ed25519(public_key: &[u8]) -> Vec<u8> {
    let alg = der_alg_id_ed25519();
    let mut bit_string = vec![0u8];
    bit_string.extend_from_slice(public_key);
    let spk = der_tlv(TAG_BIT_STRING, &bit_string);
    let mut body = alg;
    body.extend_from_slice(&spk);
    der_tlv(TAG_SEQUENCE, &body)
}

// ---------------------------------------------------------------------------
// Cert / CRL builders
// ---------------------------------------------------------------------------

fn fresh_keypair() -> Ed25519KeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

struct BuiltCert {
    der: Vec<u8>,
    serial: u64,
    keypair: Ed25519KeyPair,
}

fn build_cert(
    subject_cn: &str,
    serial: u64,
    not_before: &[u8],
    not_after: &[u8],
    issuer_cn: &str,
    issuer_kp: &Ed25519KeyPair,
) -> BuiltCert {
    let subject_kp = fresh_keypair();
    let subject_pub = subject_kp.public_key().as_ref();

    let version_inner = der_integer(2);
    let version = der_tlv(TAG_CONTEXT_0_EXPLICIT, &version_inner);
    let serial_der = der_integer(serial);
    let tbs_sig_alg = der_alg_id_ed25519();
    let issuer_name = der_common_name(issuer_cn);
    let validity_body = {
        let mut v = der_utc_time(not_before);
        v.extend_from_slice(&der_utc_time(not_after));
        v
    };
    let validity = der_tlv(TAG_SEQUENCE, &validity_body);
    let subject_name = der_common_name(subject_cn);
    let spki = der_spki_ed25519(subject_pub);

    let mut tbs_body: Vec<u8> = Vec::new();
    tbs_body.extend_from_slice(&version);
    tbs_body.extend_from_slice(&serial_der);
    tbs_body.extend_from_slice(&tbs_sig_alg);
    tbs_body.extend_from_slice(&issuer_name);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&subject_name);
    tbs_body.extend_from_slice(&spki);

    let tbs = der_tlv(TAG_SEQUENCE, &tbs_body);

    // Sign the TBS with the *issuer*'s private key.
    let sig = issuer_kp.sign(&tbs);
    let mut sig_bs = vec![0u8];
    sig_bs.extend_from_slice(sig.as_ref());
    let outer_sig_alg = der_alg_id_ed25519();
    let outer_sig_value = der_tlv(TAG_BIT_STRING, &sig_bs);

    let mut cert_body = tbs;
    cert_body.extend_from_slice(&outer_sig_alg);
    cert_body.extend_from_slice(&outer_sig_value);
    let der = der_tlv(TAG_SEQUENCE, &cert_body);

    BuiltCert { der, serial, keypair: subject_kp }
}

fn build_self_signed_ca(cn: &str, not_before: &[u8], not_after: &[u8]) -> BuiltCert {
    let kp = fresh_keypair();
    // A self-signed cert is one where issuer == subject and the
    // signing key == the SPKI key. Re-use `build_cert` by
    // handing it the same keypair for both roles, but we have
    // to do it explicitly because build_cert makes a fresh
    // subject keypair.
    let pub_bytes = kp.public_key().as_ref();

    let version_inner = der_integer(2);
    let version = der_tlv(TAG_CONTEXT_0_EXPLICIT, &version_inner);
    let serial_der = der_integer(0x01);
    let tbs_sig_alg = der_alg_id_ed25519();
    let name = der_common_name(cn);
    let validity_body = {
        let mut v = der_utc_time(not_before);
        v.extend_from_slice(&der_utc_time(not_after));
        v
    };
    let validity = der_tlv(TAG_SEQUENCE, &validity_body);
    let spki = der_spki_ed25519(pub_bytes);

    let mut tbs_body: Vec<u8> = Vec::new();
    tbs_body.extend_from_slice(&version);
    tbs_body.extend_from_slice(&serial_der);
    tbs_body.extend_from_slice(&tbs_sig_alg);
    tbs_body.extend_from_slice(&name);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&name);
    tbs_body.extend_from_slice(&spki);

    let tbs = der_tlv(TAG_SEQUENCE, &tbs_body);
    let sig = kp.sign(&tbs);
    let mut sig_bs = vec![0u8];
    sig_bs.extend_from_slice(sig.as_ref());
    let outer_sig_alg = der_alg_id_ed25519();
    let outer_sig_value = der_tlv(TAG_BIT_STRING, &sig_bs);

    let mut cert_body = tbs;
    cert_body.extend_from_slice(&outer_sig_alg);
    cert_body.extend_from_slice(&outer_sig_value);
    let der = der_tlv(TAG_SEQUENCE, &cert_body);

    BuiltCert { der, serial: 0x01, keypair: kp }
}

fn build_crl(ca_cn: &str, revoked_serials: &[u64], ca_kp: &Ed25519KeyPair) -> Vec<u8> {
    let version = der_integer(1); // v2
    let sig_alg = der_alg_id_ed25519();
    let issuer = der_common_name(ca_cn);
    let this_update = der_utc_time(b"250601000000Z");
    let next_update = der_utc_time(b"260601000000Z");

    let revoked_seq = if revoked_serials.is_empty() {
        // Omit revokedCertificates if none — matches RFC 5280
        // "absent when no certs are revoked".
        Vec::new()
    } else {
        let mut entries: Vec<u8> = Vec::new();
        for &s in revoked_serials {
            let serial_der = der_integer(s);
            let rev_date = der_utc_time(b"250615000000Z");
            let mut body = serial_der;
            body.extend_from_slice(&rev_date);
            entries.extend_from_slice(&der_tlv(TAG_SEQUENCE, &body));
        }
        der_tlv(TAG_SEQUENCE, &entries)
    };

    let mut tbs_body: Vec<u8> = Vec::new();
    tbs_body.extend_from_slice(&version);
    tbs_body.extend_from_slice(&sig_alg);
    tbs_body.extend_from_slice(&issuer);
    tbs_body.extend_from_slice(&this_update);
    tbs_body.extend_from_slice(&next_update);
    if !revoked_seq.is_empty() {
        tbs_body.extend_from_slice(&revoked_seq);
    }

    let tbs = der_tlv(TAG_SEQUENCE, &tbs_body);
    let sig = ca_kp.sign(&tbs);
    let mut sig_bs = vec![0u8];
    sig_bs.extend_from_slice(sig.as_ref());

    let mut crl_body = tbs;
    crl_body.extend_from_slice(&der_alg_id_ed25519());
    crl_body.extend_from_slice(&der_tlv(TAG_BIT_STRING, &sig_bs));
    der_tlv(TAG_SEQUENCE, &crl_body)
}

// ---------------------------------------------------------------------------
// Credential packing
// ---------------------------------------------------------------------------

/// Pack a credential blob: `[u16 BE cert_len][cert_der][64-byte sig]`.
fn pack_credential(
    cert_der: &[u8],
    leaf_kp: &Ed25519KeyPair,
    handshake_hash: &[u8; 32],
) -> Vec<u8> {
    let sig = leaf_kp.sign(handshake_hash);
    let mut blob = Vec::with_capacity(2 + cert_der.len() + 64);
    let len = cert_der.len() as u16;
    blob.extend_from_slice(&len.to_be_bytes());
    blob.extend_from_slice(cert_der);
    blob.extend_from_slice(sig.as_ref());
    blob
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Wall clock pinned to 2025-07-01 00:00:00 UTC. Picked so the
/// 2025-01-01 → 2035-01-01 "valid" window is inside and the
/// 2021-01-01 → 2022-01-01 "expired" window is outside.
const PINNED_NOW: u64 = 1_751_328_000;

fn static_clock() -> Box<dyn Fn() -> u64 + Send + Sync> {
    Box::new(|| PINNED_NOW)
}

fn dummy_noise_static() -> PublicKey {
    PublicKey([0xAAu8; 32])
}

#[test]
fn valid_leaf_signed_by_ca_with_correct_transcript_is_accepted() {
    let ca = build_self_signed_ca("desmos-mtls-ca", b"250101000000Z", b"350101000000Z");
    let leaf = build_cert(
        "desmos-client-alice",
        0x42,
        b"250101000000Z",
        b"350101000000Z",
        "desmos-mtls-ca",
        &ca.keypair,
    );
    let crl = build_crl("desmos-mtls-ca", &[], &ca.keypair);

    let authr = MtlsAuthenticator::new(MtlsConfig { ca_der: ca.der.clone(), crl_der: Some(crl) })
        .unwrap()
        .with_clock(static_clock());

    let handshake_hash = [0x11u8; 32];
    let credential = pack_credential(&leaf.der, &leaf.keypair, &handshake_hash);
    let initiator_static = dummy_noise_static();
    let ctx = AuthContext::new(&initiator_static, &handshake_hash, &credential);

    authr.authenticate(&ctx).unwrap();
    assert_eq!(authr.name(), "mtls");

    // Subject CN peeking works without a separate auth call.
    assert_eq!(authr.peek_subject_cn(&credential), Some("desmos-client-alice"));
}

#[test]
fn expired_leaf_is_rejected() {
    let ca = build_self_signed_ca("desmos-mtls-ca", b"200101000000Z", b"350101000000Z");
    // Leaf validity ends before the pinned clock.
    let leaf = build_cert(
        "expired-client",
        0x43,
        b"210101000000Z",
        b"220101000000Z",
        "desmos-mtls-ca",
        &ca.keypair,
    );

    let authr = MtlsAuthenticator::new(MtlsConfig { ca_der: ca.der.clone(), crl_der: None })
        .unwrap()
        .with_clock(static_clock());

    let handshake_hash = [0x22u8; 32];
    let credential = pack_credential(&leaf.der, &leaf.keypair, &handshake_hash);
    let initiator_static = dummy_noise_static();
    let ctx = AuthContext::new(&initiator_static, &handshake_hash, &credential);

    assert_eq!(authr.authenticate(&ctx), Err(AuthError::Rejected));
}

#[test]
fn revoked_leaf_is_rejected() {
    let ca = build_self_signed_ca("desmos-mtls-ca", b"250101000000Z", b"350101000000Z");
    let leaf = build_cert(
        "revoked-client",
        0x99,
        b"250101000000Z",
        b"350101000000Z",
        "desmos-mtls-ca",
        &ca.keypair,
    );
    let crl = build_crl("desmos-mtls-ca", &[leaf.serial], &ca.keypair);

    let authr = MtlsAuthenticator::new(MtlsConfig { ca_der: ca.der.clone(), crl_der: Some(crl) })
        .unwrap()
        .with_clock(static_clock());

    let handshake_hash = [0x33u8; 32];
    let credential = pack_credential(&leaf.der, &leaf.keypair, &handshake_hash);
    let initiator_static = dummy_noise_static();
    let ctx = AuthContext::new(&initiator_static, &handshake_hash, &credential);

    assert_eq!(authr.authenticate(&ctx), Err(AuthError::Rejected));
}

#[test]
fn leaf_signed_by_different_ca_is_rejected() {
    let trusted_ca = build_self_signed_ca("desmos-mtls-ca", b"250101000000Z", b"350101000000Z");
    let other_ca = build_self_signed_ca("evil-ca", b"250101000000Z", b"350101000000Z");

    // Leaf chained to the *other* CA, not the trusted one.
    let leaf = build_cert(
        "impostor-client",
        0xAA,
        b"250101000000Z",
        b"350101000000Z",
        "evil-ca",
        &other_ca.keypair,
    );

    let authr =
        MtlsAuthenticator::new(MtlsConfig { ca_der: trusted_ca.der.clone(), crl_der: None })
            .unwrap()
            .with_clock(static_clock());

    let handshake_hash = [0x44u8; 32];
    let credential = pack_credential(&leaf.der, &leaf.keypair, &handshake_hash);
    let initiator_static = dummy_noise_static();
    let ctx = AuthContext::new(&initiator_static, &handshake_hash, &credential);

    assert_eq!(authr.authenticate(&ctx), Err(AuthError::Rejected));
}

#[test]
fn transcript_signature_over_wrong_hash_is_rejected() {
    let ca = build_self_signed_ca("desmos-mtls-ca", b"250101000000Z", b"350101000000Z");
    let leaf = build_cert(
        "replay-attempt",
        0x55,
        b"250101000000Z",
        b"350101000000Z",
        "desmos-mtls-ca",
        &ca.keypair,
    );

    let authr = MtlsAuthenticator::new(MtlsConfig { ca_der: ca.der.clone(), crl_der: None })
        .unwrap()
        .with_clock(static_clock());

    // Client signs a *different* hash than the one the server
    // is binding to.
    let client_hash = [0x55u8; 32];
    let server_hash = [0x66u8; 32];
    let credential = pack_credential(&leaf.der, &leaf.keypair, &client_hash);
    let initiator_static = dummy_noise_static();
    let ctx = AuthContext::new(&initiator_static, &server_hash, &credential);

    assert_eq!(authr.authenticate(&ctx), Err(AuthError::Rejected));
}

#[test]
fn truncated_credential_is_rejected() {
    let ca = build_self_signed_ca("desmos-mtls-ca", b"250101000000Z", b"350101000000Z");
    let leaf = build_cert(
        "alice",
        0x01,
        b"250101000000Z",
        b"350101000000Z",
        "desmos-mtls-ca",
        &ca.keypair,
    );

    let authr = MtlsAuthenticator::new(MtlsConfig { ca_der: ca.der.clone(), crl_der: None })
        .unwrap()
        .with_clock(static_clock());

    let handshake_hash = [0u8; 32];
    let full = pack_credential(&leaf.der, &leaf.keypair, &handshake_hash);
    // Chop the Ed25519 signature down to 32 bytes.
    let truncated = &full[..full.len() - 32];
    let initiator_static = dummy_noise_static();
    let ctx = AuthContext::new(&initiator_static, &handshake_hash, truncated);

    assert_eq!(authr.authenticate(&ctx), Err(AuthError::Rejected));
}

#[test]
fn init_rejects_crl_signed_by_foreign_ca() {
    let ca_a = build_self_signed_ca("ca-alpha", b"250101000000Z", b"350101000000Z");
    let ca_b = build_self_signed_ca("ca-bravo", b"250101000000Z", b"350101000000Z");
    // CRL issuer CN is ca-alpha but the signature comes from
    // ca-bravo's key → `new()` must reject at load time.
    let bad_crl = build_crl("ca-alpha", &[0x01], &ca_b.keypair);

    let err =
        MtlsAuthenticator::new(MtlsConfig { ca_der: ca_a.der.clone(), crl_der: Some(bad_crl) })
            .unwrap_err();
    // We only care that `new()` refused the config; the exact
    // enum variant is an implementation detail that may shift.
    let _ = err;
}
