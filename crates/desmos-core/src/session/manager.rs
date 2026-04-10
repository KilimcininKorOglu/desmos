//! `SessionTable`: the global map from `SessionId` to an active session.
//!
//! The table is read-heavy (every inbound packet looks up its session)
//! and write-light (inserts on new connections, removes on close, state
//! transitions under per-slot locks). `RwLock<HashMap<SessionId, _>>`
//! is the right shape: writers block readers only for the O(1) HashMap
//! mutation, and the per-slot `Mutex` keeps state transitions from
//! racing each other without holding the outer RwLock.
//!
//! The stored value is [`AnySession`], an enum over the four typestate
//! markers from the parent module. The typestate guarantee is preserved
//! at call sites: the caller takes a specific variant out, performs a
//! transition, and writes the new variant back.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use desmos_proto::SessionId;

use super::Closed;
use super::Established;
use super::Handshaking;
use super::Rekeying;
use super::Session;

/// Erased-state wrapper used as the table's value. The typestate
/// guarantee is restored by pattern-matching on this enum.
///
/// The enum carries large variants (`Session<Established>` holds two
/// ~600-byte `ring::aead::LessSafeKey` slabs) but each slot sits
/// behind an `Arc<Mutex<_>>`, so only one allocation per session pays
/// for the worst case.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum AnySession {
    Handshaking(Session<Handshaking>),
    Established(Session<Established>),
    Rekeying(Session<Rekeying>),
    Closed(Session<Closed>),
}

impl AnySession {
    pub fn id(&self) -> SessionId {
        match self {
            Self::Handshaking(s) => s.id(),
            Self::Established(s) => s.id(),
            Self::Rekeying(s) => s.id(),
            Self::Closed(s) => s.id(),
        }
    }

    /// Cheap discriminant for metrics / assertions without matching the
    /// whole enum every time.
    pub fn state_name(&self) -> &'static str {
        match self {
            Self::Handshaking(_) => "handshaking",
            Self::Established(_) => "established",
            Self::Rekeying(_) => "rekeying",
            Self::Closed(_) => "closed",
        }
    }
}

impl From<Session<Handshaking>> for AnySession {
    fn from(s: Session<Handshaking>) -> Self {
        Self::Handshaking(s)
    }
}

impl From<Session<Established>> for AnySession {
    fn from(s: Session<Established>) -> Self {
        Self::Established(s)
    }
}

impl From<Session<Rekeying>> for AnySession {
    fn from(s: Session<Rekeying>) -> Self {
        Self::Rekeying(s)
    }
}

impl From<Session<Closed>> for AnySession {
    fn from(s: Session<Closed>) -> Self {
        Self::Closed(s)
    }
}

/// Handle to a session slot. Cloning the slot is cheap — it only bumps
/// the `Arc` refcount — so call sites can grab a slot under a short-
/// lived read lock and release the outer lock before touching the
/// per-slot `Mutex`.
pub type Slot = Arc<Mutex<AnySession>>;

/// Global session table. Multiple readers may look up concurrently; a
/// writer blocks readers only for the O(1) map mutation.
#[derive(Default)]
pub struct SessionTable {
    slots: RwLock<HashMap<SessionId, Slot>>,
}

impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live slots in the table. Takes a read lock.
    pub fn len(&self) -> usize {
        self.slots.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert a new session. Returns the previous slot if one was
    /// already installed under the same id — callers that expect unique
    /// ids should treat a `Some` return as a bug.
    pub fn insert(&self, session: impl Into<AnySession>) -> Option<Slot> {
        let any = session.into();
        let id = any.id();
        let slot = Arc::new(Mutex::new(any));
        self.slots.write().unwrap().insert(id, slot)
    }

    /// Look up a slot by id. Returns a cloned `Arc` handle so the caller
    /// can drop the outer read lock before acquiring the per-slot lock.
    pub fn get(&self, id: SessionId) -> Option<Slot> {
        self.slots.read().unwrap().get(&id).cloned()
    }

    /// Remove a session from the table. Returns the removed slot if it
    /// was present.
    pub fn remove(&self, id: SessionId) -> Option<Slot> {
        self.slots.write().unwrap().remove(&id)
    }

    /// Collect every live session id. Useful for periodic scans
    /// (keepalive, rekey, stale cleanup).
    pub fn ids(&self) -> Vec<SessionId> {
        self.slots.read().unwrap().keys().copied().collect()
    }

    /// `true` if the table currently holds a slot for `id`.
    pub fn contains(&self, id: SessionId) -> bool {
        self.slots.read().unwrap().contains_key(&id)
    }
}

impl core::fmt::Debug for SessionTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionTable").field("len", &self.len()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;
    use desmos_proto::crypto::x25519::X25519PrivateKey;

    fn dummy_handshaking(id: u16) -> Session<Handshaking> {
        let sk = X25519PrivateKey::from_bytes([0x11; 32]);
        let peer = X25519PrivateKey::from_bytes([0x22; 32]).public_key();
        Session::<Handshaking>::new_initiator(SessionId(id), sk, peer, b"test")
    }

    #[test]
    fn new_table_is_empty() {
        let t = SessionTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn insert_and_get_roundtrip() {
        let t = SessionTable::new();
        assert!(t.insert(dummy_handshaking(1)).is_none());
        assert_eq!(t.len(), 1);
        let slot = t.get(SessionId(1)).unwrap();
        assert_eq!(slot.lock().unwrap().id(), SessionId(1));
    }

    #[test]
    fn get_missing_returns_none() {
        let t = SessionTable::new();
        assert!(t.get(SessionId(99)).is_none());
    }

    #[test]
    fn remove_returns_previously_inserted_slot() {
        let t = SessionTable::new();
        t.insert(dummy_handshaking(3));
        let slot = t.remove(SessionId(3)).unwrap();
        assert_eq!(slot.lock().unwrap().id(), SessionId(3));
        assert!(t.is_empty());
        assert!(t.remove(SessionId(3)).is_none());
    }

    #[test]
    fn insert_duplicate_returns_previous_slot() {
        let t = SessionTable::new();
        t.insert(dummy_handshaking(5));
        let evicted = t.insert(dummy_handshaking(5));
        assert!(evicted.is_some());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn ids_lists_every_live_session() {
        let t = SessionTable::new();
        t.insert(dummy_handshaking(1));
        t.insert(dummy_handshaking(2));
        t.insert(dummy_handshaking(3));
        let mut ids = t.ids();
        ids.sort_by_key(|i| i.0);
        assert_eq!(ids, vec![SessionId(1), SessionId(2), SessionId(3)]);
    }

    #[test]
    fn contains_reflects_insert_and_remove() {
        let t = SessionTable::new();
        assert!(!t.contains(SessionId(9)));
        t.insert(dummy_handshaking(9));
        assert!(t.contains(SessionId(9)));
        t.remove(SessionId(9));
        assert!(!t.contains(SessionId(9)));
    }

    /// Deterministic xorshift64-driven property test. Proptest is
    /// blocked on MSRV 1.75 (see `MEMORY.md`), so we hand-roll a fuzzer
    /// that does 10 000 random ops against the real table and a
    /// reference `HashMap` and checks they stay in sync.
    #[test]
    fn fuzz_insert_lookup_remove_stays_consistent_with_reference() {
        let t = SessionTable::new();
        let mut reference: HashMap<u16, bool> = HashMap::new();
        let mut rng = Xorshift64::new(0xDE5D_0500_5E55_1007);

        for _ in 0..10_000 {
            // Small id space so collisions happen constantly.
            let id = (rng.next_u64() % 32) as u16;
            let sid = SessionId(id);
            match rng.next_u64() % 4 {
                0 => {
                    // insert
                    let prev = t.insert(dummy_handshaking(id));
                    assert_eq!(prev.is_some(), reference.contains_key(&id));
                    reference.insert(id, true);
                }
                1 => {
                    // get
                    assert_eq!(t.contains(sid), reference.contains_key(&id));
                    assert_eq!(t.get(sid).is_some(), reference.contains_key(&id));
                }
                2 => {
                    // remove
                    let had = reference.remove(&id).is_some();
                    assert_eq!(t.remove(sid).is_some(), had);
                }
                3 => {
                    // contains
                    assert_eq!(t.contains(sid), reference.contains_key(&id));
                }
                _ => unreachable!(),
            }
            assert_eq!(t.len(), reference.len());
        }
    }

    /// Minimal xorshift64 RNG — same pattern used in the TOML and wire
    /// round-trip fuzzers across the workspace.
    struct Xorshift64 {
        state: u64,
    }

    impl Xorshift64 {
        fn new(seed: u64) -> Self {
            Self { state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed } }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x
        }
    }
}
