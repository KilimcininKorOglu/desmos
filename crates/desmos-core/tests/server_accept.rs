//! Integration test for Task 30: multi-client server listener.
//!
//! Covers the three acceptance items from TASKS.md Task 30:
//!
//! 1. Two clients connect simultaneously with distinct
//!    `SessionId`s — driven from two threads so the test actually
//!    exercises `ClientRegistry::accept_client_msg1` under
//!    concurrent access, not just back-to-back calls.
//! 2. Server exits cleanly on `desmos down` — modelled as a
//!    `shutdown()` call that drains every session out of the
//!    `SessionTable` and leaves the registry with zero active
//!    clients.
//! 3. `max_clients` enforced — a third client attempting to join
//!    a 2-slot registry gets `ServerError::MaxClientsReached`
//!    before any crypto runs.
//!
//! Also closes the "SessionTable orphan" gap that has been in
//! MEMORY.md since Task 19: for the first time, a data-plane
//! test looks up a live session by id out of the table and
//! successfully encrypt→decrypts packets through it.

use std::sync::Arc;
use std::thread;

use desmos_core::server::ClientRegistry;
use desmos_core::server::ServerError;
use desmos_core::session::AnySession;
use desmos_proto::crypto::x25519::PublicKey;
use desmos_proto::crypto::x25519::X25519PrivateKey;
use desmos_proto::handshake::Initiator;
use desmos_proto::SessionId;

fn server_static() -> X25519PrivateKey {
    X25519PrivateKey::from_bytes([0x22; 32])
}

fn client_static(seed: u8) -> X25519PrivateKey {
    X25519PrivateKey::from_bytes([seed; 32])
}

const PROLOGUE: &[u8] = b"desmos-server-accept-test";

/// Produce the msg1 bytes a client would put on the wire and
/// return the initiator instance alongside so the test can
/// consume it via `read_message_2` after the server responds.
fn new_client(seed: u8, server_pub: PublicKey) -> (Initiator, Vec<u8>) {
    let mut ini = Initiator::new(client_static(seed), server_pub, PROLOGUE);
    let msg1 = ini.write_message_1().unwrap();
    (ini, msg1)
}

#[test]
fn two_clients_complete_concurrently_with_distinct_session_ids() {
    // Arc the registry so both threads can hammer it at once. The
    // underlying SessionTable uses RwLock<HashMap> so concurrent
    // accept_client_msg1 calls are legal and expected.
    let reg = Arc::new(ClientRegistry::new(server_static(), Vec::new(), PROLOGUE.to_vec(), 10));
    let server_pub = server_static().public_key();

    let reg_a = Arc::clone(&reg);
    let reg_b = Arc::clone(&reg);
    let handle_a = thread::spawn(move || {
        let (ini, msg1) = new_client(0x11, server_pub);
        let (sid, msg2) = reg_a.accept_client_msg1(&msg1, 0).unwrap();
        // Client can finish its own side of the handshake.
        let keys = ini.read_message_2(&msg2).unwrap();
        (sid, keys.handshake_hash)
    });
    let handle_b = thread::spawn(move || {
        let (ini, msg1) = new_client(0x33, server_pub);
        let (sid, msg2) = reg_b.accept_client_msg1(&msg1, 0).unwrap();
        let keys = ini.read_message_2(&msg2).unwrap();
        (sid, keys.handshake_hash)
    });
    let (sid_a, hash_a) = handle_a.join().unwrap();
    let (sid_b, hash_b) = handle_b.join().unwrap();

    assert_ne!(sid_a, sid_b);
    assert_eq!(reg.active_clients(), 2);
    // The two handshakes produced genuinely distinct transcripts.
    assert_ne!(hash_a, hash_b);

    // Both sessions live in the table as `Established` and map
    // back to the ids the registry handed out.
    for sid in [sid_a, sid_b] {
        let slot = reg.table().get(sid).expect("session in table");
        let guard = slot.lock().unwrap();
        match &*guard {
            AnySession::Established(s) => assert_eq!(s.id(), sid),
            other => panic!("expected Established for {sid:?}, got {other:?}"),
        }
    }
}

#[test]
fn max_clients_cap_rejects_the_third_connector() {
    let reg = ClientRegistry::new(server_static(), Vec::new(), PROLOGUE.to_vec(), 2);
    let server_pub = server_static().public_key();

    for seed in [0x11u8, 0x22] {
        let (_ini, msg1) = new_client(seed, server_pub);
        reg.accept_client_msg1(&msg1, 0).unwrap();
    }
    assert_eq!(reg.active_clients(), 2);

    let (_ini, msg1) = new_client(0x44, server_pub);
    let err = reg.accept_client_msg1(&msg1, 0).unwrap_err();
    assert!(matches!(err, ServerError::MaxClientsReached), "got {err:?}");
    assert_eq!(reg.active_clients(), 2);
}

#[test]
fn shutdown_drains_every_session_and_matches_desmos_down_semantics() {
    let reg = ClientRegistry::new(server_static(), Vec::new(), PROLOGUE.to_vec(), 10);
    let server_pub = server_static().public_key();

    let mut client_session_ids = Vec::new();
    for seed in [0x11u8, 0x22, 0x33, 0x44] {
        let (_ini, msg1) = new_client(seed, server_pub);
        let (sid, _msg2) = reg.accept_client_msg1(&msg1, 0).unwrap();
        client_session_ids.push(sid);
    }
    assert_eq!(reg.active_clients(), 4);

    let drained = reg.shutdown();
    assert_eq!(drained.len(), 4);
    assert_eq!(reg.active_clients(), 0);

    // Every previously-issued session id is now absent from the
    // table.
    for sid in client_session_ids {
        assert!(reg.table().get(sid).is_none(), "{sid:?} still present");
    }

    // A second shutdown is a clean no-op — the daemon can call it
    // unconditionally from its signal handler.
    assert!(reg.shutdown().is_empty());
}

#[test]
fn server_side_encrypt_and_client_side_decrypt_via_session_table() {
    // The "SessionTable orphan closed" moment: accept a client
    // msg1, look the resulting session up out of the table by id,
    // and exchange a data-plane packet across the two halves.
    let reg = ClientRegistry::new(server_static(), Vec::new(), PROLOGUE.to_vec(), 10);
    let server_pub = server_static().public_key();
    let (ini, msg1) = new_client(0x11, server_pub);

    let (sid, msg2) = reg.accept_client_msg1(&msg1, 0).unwrap();
    let client_established = ini.read_message_2(&msg2).unwrap();

    // Client seals a packet using its own handshake output.
    let client_send_key =
        desmos_proto::crypto::aead::AeadKey::new(&client_established.send).unwrap();
    let plaintext = b"hello server from client table";
    let mut wire = plaintext.to_vec();
    let nonce = build_nonce(0);
    let aad = build_aad(sid, 0);
    client_send_key.seal_in_place(&nonce, &aad, &mut wire).unwrap();

    // Server side: look up the session via the registry's
    // `SessionTable` and decrypt. This is the code path the
    // inbound pipeline will run for every received datagram in
    // Phase 4+ — the lookup returns the same `AnySession` variant
    // the accept call installed.
    let slot = reg.table().get(sid).expect("server slot");
    let guard = slot.lock().unwrap();
    let plaintext_out = match &*guard {
        AnySession::Established(session) => {
            let mut buf = wire.clone();
            session.decrypt_data(0, &mut buf).unwrap()
        }
        other => panic!("expected Established, got {other:?}"),
    };
    assert_eq!(plaintext_out, plaintext);
}

// ---------------------------------------------------------------------------
// Nonce + AAD helpers that mirror `session::mod::build_nonce` /
// `build_aad`. The helpers are private there, but every pipeline
// call site replicates the same layout, so the test does too.
// ---------------------------------------------------------------------------

fn build_nonce(seq: u64) -> [u8; desmos_proto::crypto::aead::NONCE_LEN] {
    let mut n = [0u8; desmos_proto::crypto::aead::NONCE_LEN];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn build_aad(id: SessionId, seq: u64) -> [u8; 10] {
    let mut aad = [0u8; 10];
    aad[..2].copy_from_slice(&id.0.to_be_bytes());
    aad[2..].copy_from_slice(&seq.to_be_bytes());
    aad
}
