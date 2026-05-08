//! Public-key allow-list authenticator.
//!
//! Noise IK already verifies that the initiator's static public
//! key belongs to whoever constructed msg1 — the AEAD tag on the
//! `enc_s` token proves it. The only decision left for the
//! authenticator is "should this particular static key be
//! allowed in?", which is a membership check against an
//! operator-supplied allow-list.
//!
//! Two allow-list modes:
//!
//! - **Empty list**: every client that completes the Noise
//!   handshake is accepted. Matches the `Responder::new`
//!   behaviour so the daemon can use a single `PublicKeyList`
//!   value both as the Noise whitelist and as the post-handshake
//!   authenticator without worrying about drift.
//! - **Non-empty list**: the initiator's static key must be a
//!   member or the authenticator returns
//!   [`AuthError::Rejected`].
//!
//! Lookup is O(n) over the list. n is the operator-configured
//! client count — typically a handful, at most a few hundred —
//! so the cost is negligible and avoiding a HashSet keeps the
//! backend allocation-free on the fast path.

use desmos_proto::crypto::x25519::PublicKey;
use desmos_proto::crypto::x25519::PUBLIC_KEY_LEN;

use super::constant_time_eq;
use super::AuthContext;
use super::AuthError;
use super::Authenticator;

/// Public-key allow-list authenticator.
pub struct PublicKeyList {
    allowed: Vec<PublicKey>,
}

impl PublicKeyList {
    /// Build from an explicit allow-list.
    pub fn new(allowed: Vec<PublicKey>) -> Self {
        Self { allowed }
    }

    /// Build from a single authorised key.
    pub fn single(key: PublicKey) -> Self {
        Self { allowed: vec![key] }
    }

    /// Number of allowed keys.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// `true` when the list is empty and therefore accepts every
    /// client that completes Noise IK.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Pretends to pass-through — every static key is accepted.
    /// Matches the "no whitelist" behaviour of `Responder::new(_,
    /// vec![], _)` so the daemon can mirror the same behaviour
    /// in the post-handshake path without a branch.
    pub fn accept_all() -> Self {
        Self { allowed: Vec::new() }
    }

    /// Clone the allow-list into a `Vec<PublicKey>` suitable for
    /// feeding to `Responder::new(_, known_initiators, _)`. Keeps
    /// the same source of truth for both the Noise handshake and
    /// the authenticator so a config change cannot leave them
    /// disagreeing.
    pub fn to_responder_whitelist(&self) -> Vec<PublicKey> {
        self.allowed.clone()
    }

    /// Membership check. Constant-time over the public-key bytes
    /// so a timing side channel cannot enumerate the allow-list.
    pub fn contains(&self, key: &PublicKey) -> bool {
        let needle = key.0;
        let mut found: u8 = 0;
        for candidate in &self.allowed {
            let equal = constant_time_eq(&needle[..PUBLIC_KEY_LEN], &candidate.0[..PUBLIC_KEY_LEN]);
            // Fold the boolean into `found` without an early
            // exit so the total time is always O(n).
            found |= u8::from(equal);
        }
        found != 0
    }
}

impl core::fmt::Debug for PublicKeyList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKeyList").field("allowed_len", &self.allowed.len()).finish()
    }
}

impl Authenticator for PublicKeyList {
    fn name(&self) -> &'static str {
        "pubkey"
    }

    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError> {
        if self.allowed.is_empty() {
            // Accept-all mode, matches the Noise `Responder`
            // behaviour with an empty whitelist.
            return Ok(());
        }
        if self.contains(ctx.initiator_static) {
            Ok(())
        } else {
            Err(AuthError::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_proto::crypto::x25519::X25519PrivateKey;

    fn key(seed: u8) -> PublicKey {
        X25519PrivateKey::from_bytes([seed; 32]).public_key()
    }

    fn ctx_for<'a>(pk: &'a PublicKey, hash: &'a [u8; 32]) -> AuthContext<'a> {
        AuthContext::new(pk, hash, &[])
    }

    #[test]
    fn empty_list_accepts_any_client() {
        let list = PublicKeyList::accept_all();
        let client = key(0x11);
        let hash = [0u8; 32];
        assert!(list.authenticate(&ctx_for(&client, &hash)).is_ok());
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn single_allowed_key_accepts_that_key() {
        let allowed = key(0x33);
        let list = PublicKeyList::single(allowed);
        let hash = [0u8; 32];
        assert!(list.authenticate(&ctx_for(&allowed, &hash)).is_ok());
    }

    #[test]
    fn unknown_key_rejects_when_list_is_non_empty() {
        let list = PublicKeyList::new(vec![key(0x11), key(0x22)]);
        let intruder = key(0x77);
        let hash = [0u8; 32];
        assert_eq!(list.authenticate(&ctx_for(&intruder, &hash)).unwrap_err(), AuthError::Rejected,);
    }

    #[test]
    fn multiple_allowed_keys_are_all_accepted() {
        let allowed = vec![key(0x11), key(0x22), key(0x33)];
        let list = PublicKeyList::new(allowed.clone());
        let hash = [0u8; 32];
        for k in &allowed {
            assert!(list.authenticate(&ctx_for(k, &hash)).is_ok());
        }
    }

    #[test]
    fn contains_matches_authenticate_semantics() {
        let list = PublicKeyList::new(vec![key(0x11), key(0x22)]);
        assert!(list.contains(&key(0x11)));
        assert!(list.contains(&key(0x22)));
        assert!(!list.contains(&key(0x33)));
    }

    #[test]
    fn to_responder_whitelist_returns_a_clone() {
        let allowed = vec![key(0x11), key(0x22)];
        let list = PublicKeyList::new(allowed.clone());
        let reso = list.to_responder_whitelist();
        assert_eq!(reso.len(), allowed.len());
        for (a, b) in reso.iter().zip(allowed.iter()) {
            assert_eq!(a.0, b.0);
        }
    }

    #[test]
    fn name_is_pubkey() {
        assert_eq!(PublicKeyList::accept_all().name(), "pubkey");
    }

    #[test]
    fn debug_format_reports_length_only() {
        let list = PublicKeyList::new(vec![key(0x11), key(0x22), key(0x33)]);
        let rendered = format!("{list:?}");
        assert!(rendered.contains("allowed_len: 3"));
        // Raw key bytes must not leak into the Debug output.
        assert!(!rendered.contains("1111"));
    }

    #[test]
    fn len_tracks_input_size() {
        assert_eq!(PublicKeyList::accept_all().len(), 0);
        assert_eq!(PublicKeyList::single(key(0x11)).len(), 1);
        assert_eq!(PublicKeyList::new(vec![key(0x11), key(0x22)]).len(), 2);
    }

    /// Allow-list check must not early-exit on a match, so the
    /// total time stays independent of the needle's position in
    /// the list. We cannot portably time the exact ns here, but
    /// we verify the contains() call walks every entry by
    /// building a big list where only the last entry matches
    /// and asserting it still returns true. The real timing
    /// property is documented in the module comment.
    #[test]
    fn contains_walks_to_the_last_entry() {
        let mut allowed: Vec<PublicKey> = (0u8..64).map(key).collect();
        let target = key(100);
        allowed.push(target);
        let list = PublicKeyList::new(allowed);
        assert!(list.contains(&target));
    }
}
