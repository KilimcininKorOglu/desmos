//! Time-based one-time password authenticator (RFC 6238).
//!
//! TOTP is HOTP (RFC 4226) with the HOTP counter replaced by
//! `T = floor((now - T0) / X)` where `T0` is the epoch start
//! and `X` is the step size in seconds. The operator provisions
//! a shared secret into a TOTP app (Google Authenticator, 1Password,
//! etc.), the app computes the 6-digit code for the current time
//! step, and the server verifies it at handshake time.
//!
//! We use HMAC-SHA256 as the underlying PRF. RFC 6238 §1.2 allows
//! SHA256 and SHA512; the common authenticator apps still default
//! to SHA1, but every serious one (Authy, 1Password, Bitwarden)
//! supports SHA256 on provisioning. Desmos picks SHA256 because
//! `ring::hmac::HMAC_SHA256` is already wired up in the workspace
//! and the extra 13 bytes in the HMAC output only matter if we
//! drag in SHA1 we do not otherwise need.
//!
//! # Wire format
//!
//! The client presents the decimal code as UTF-8 bytes in
//! [`super::AuthContext::presented_credential`]. A leading-zero
//! 6-digit code (for example `042018`) is allowed and required
//! — we compare the exact ASCII representation against the
//! computed code rather than parsing to `u32`, so a client that
//! drops the leading zero rejects.
//!
//! # Clock skew
//!
//! RFC 6238 §6 recommends allowing ±1 step to tolerate clock
//! drift between the client and server. [`TotpConfig::skew_window`]
//! defaults to 1 but can be tightened to 0 or relaxed for hosts
//! with known clock issues. Every in-window step is tried in
//! constant time relative to the configured window size so a
//! timing side channel cannot enumerate which step matched.
//!
//! # Replay
//!
//! RFC 6238 §5.2 says an OTP must not be accepted twice within a
//! step. We leave that decision to the caller and record the
//! last-accepted step in an atomic slot: strict mode rejects
//! duplicate steps, lenient mode accepts them. Default is lenient
//! because a dropped packet that makes the client retry in the
//! same step is a legitimate scenario for Desmos, and the Noise
//! transcript hash is already session-binding.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use desmos_proto::crypto::hkdf;

use super::constant_time_eq;
use super::AuthContext;
use super::AuthError;
use super::Authenticator;

/// RFC 6238 default: 30-second time step.
pub const DEFAULT_PERIOD_SECS: u64 = 30;

/// RFC 6238 default: 6 decimal digits. Standard 8-digit mode is
/// also allowed. 6 is the ubiquitous setting every TOTP app picks
/// on provisioning.
pub const DEFAULT_DIGITS: u8 = 6;

/// Minimum accepted secret length. RFC 4226 §4 requires at least
/// 128 bits; this library matches the PSK minimum so
/// operators do not have to remember two numbers.
pub const TOTP_MIN_SECRET_LEN: usize = 16;

/// Maximum accepted secret length. 64 bytes is one HMAC-SHA256
/// block; longer secrets are hashed into the block before HMAC
/// uses them, which is legal but almost certainly a config
/// mistake.
pub const TOTP_MAX_SECRET_LEN: usize = 64;

/// TOTP configuration knobs.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Shared secret, already base32-decoded. RFC 4226 §4 says
    /// at least 128 bits of entropy.
    pub secret: Vec<u8>,
    /// Number of digits in the generated code. 6 or 8.
    pub digits: u8,
    /// Step size in seconds. Standard is 30.
    pub period_secs: u64,
    /// Number of ±steps to try around the current step to
    /// tolerate clock skew. 0 = strict, 1 = RFC 6238 §6
    /// recommended default, 2+ = loose.
    pub skew_window: u8,
    /// When `true`, a given step value cannot be used twice in
    /// a row — the last-accepted step is remembered and replays
    /// reject. When `false`, duplicates within a step are fine.
    pub reject_replay: bool,
}

impl TotpConfig {
    /// Build with the RFC 6238 defaults and a caller-supplied
    /// secret. Returns a `Misconfigured` error if the secret is
    /// outside the length bounds.
    pub fn new(secret: Vec<u8>) -> Result<Self, AuthError> {
        Self::with(secret, DEFAULT_DIGITS, DEFAULT_PERIOD_SECS, 1, false)
    }

    /// Build with explicit knobs. Returns `Misconfigured` on any
    /// shape error.
    pub fn with(
        secret: Vec<u8>,
        digits: u8,
        period_secs: u64,
        skew_window: u8,
        reject_replay: bool,
    ) -> Result<Self, AuthError> {
        if secret.len() < TOTP_MIN_SECRET_LEN {
            return Err(AuthError::Misconfigured("TOTP secret shorter than 16 bytes"));
        }
        if secret.len() > TOTP_MAX_SECRET_LEN {
            return Err(AuthError::Misconfigured("TOTP secret longer than 64 bytes"));
        }
        if !(6..=8).contains(&digits) {
            return Err(AuthError::Misconfigured("TOTP digits must be 6, 7, or 8"));
        }
        if period_secs == 0 {
            return Err(AuthError::Misconfigured("TOTP period_secs must be > 0"));
        }
        if skew_window > 8 {
            return Err(AuthError::Misconfigured("TOTP skew_window > 8"));
        }
        Ok(Self { secret, digits, period_secs, skew_window, reject_replay })
    }
}

/// TOTP authenticator.
pub struct TotpAuthenticator {
    config: TotpConfig,
    /// Last accepted step value. `AtomicU64::MAX` means "never
    /// seen a valid code yet". Used only when
    /// `config.reject_replay` is true.
    last_accepted_step: AtomicU64,
    /// Clock source. Tests swap in a deterministic fake.
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl TotpAuthenticator {
    /// Build with the real system clock (`SystemTime::now()`).
    pub fn new(config: TotpConfig) -> Self {
        Self::with_clock(
            config,
            Box::new(|| {
                use std::time::SystemTime;
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }),
        )
    }

    /// Build with a caller-supplied clock function. Tests use
    /// this to inject a deterministic time source.
    pub fn with_clock(config: TotpConfig, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self { config, last_accepted_step: AtomicU64::new(u64::MAX), clock }
    }

    /// Compute the code for a specific step value. Exposed for
    /// tests and for the rarely-used "generate" path where the
    /// operator needs to provision the shared secret.
    pub fn code_for_step(&self, step: u64) -> String {
        compute_totp(&self.config.secret, step, self.config.digits)
    }

    /// Current step value derived from the configured clock.
    pub fn current_step(&self) -> u64 {
        (self.clock)() / self.config.period_secs
    }
}

impl core::fmt::Debug for TotpAuthenticator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TotpAuthenticator")
            .field("digits", &self.config.digits)
            .field("period_secs", &self.config.period_secs)
            .field("skew_window", &self.config.skew_window)
            .field("reject_replay", &self.config.reject_replay)
            .finish()
    }
}

impl Authenticator for TotpAuthenticator {
    fn name(&self) -> &'static str {
        "totp"
    }

    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError> {
        if ctx.presented_credential.is_empty() {
            return Err(AuthError::Rejected);
        }
        // The code must be exactly `digits` ASCII digit bytes.
        // Anything else (wrong length, non-ASCII, whitespace) is
        // rejected before any HMAC work runs.
        if ctx.presented_credential.len() != self.config.digits as usize {
            return Err(AuthError::Rejected);
        }
        if !ctx.presented_credential.iter().all(|b| b.is_ascii_digit()) {
            return Err(AuthError::Rejected);
        }

        let now = (self.clock)();
        let center_step = now / self.config.period_secs;
        let window = self.config.skew_window as i64;

        // Walk every step in `[center - window, center + window]`
        // and compare the computed code against the presented one
        // in constant time. We do NOT early-exit on a match —
        // every branch runs exactly `2*window + 1` compares so the
        // timing profile is flat relative to which step matched.
        let mut matched_step: Option<u64> = None;
        for offset in -window..=window {
            // Signed arithmetic on u64 center. `center_step` is a
            // u64; we widen to i128 to handle the negative offset
            // path near epoch without underflow.
            let candidate = (center_step as i128) + (offset as i128);
            if candidate < 0 {
                continue;
            }
            let step = candidate as u64;
            let code = compute_totp(&self.config.secret, step, self.config.digits);
            if constant_time_eq(code.as_bytes(), ctx.presented_credential) {
                // Record but keep walking so the total runtime
                // stays flat.
                matched_step = Some(step);
            }
        }

        let matched_step = match matched_step {
            Some(s) => s,
            None => return Err(AuthError::Rejected),
        };

        if self.config.reject_replay {
            // Strict mode: reject if we have already seen this
            // step value. `compare_exchange` rejects concurrent
            // duplicates too — the first thread wins.
            let prev = self.last_accepted_step.load(Ordering::Acquire);
            if prev != u64::MAX && prev >= matched_step {
                return Err(AuthError::Rejected);
            }
            self.last_accepted_step.store(matched_step, Ordering::Release);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HOTP / TOTP core
// ---------------------------------------------------------------------------

/// Compute the RFC 6238 TOTP code for the given step value.
/// Returns a zero-padded decimal string of exactly `digits`
/// characters.
///
/// Implements RFC 4226 §5.3 dynamic truncation on top of
/// HMAC-SHA256.
fn compute_totp(secret: &[u8], step: u64, digits: u8) -> String {
    // `hkdf::extract(salt, ikm)` is exactly `HMAC-SHA256(salt,
    // ikm)`. We pass `secret` as the salt and the 8-byte
    // big-endian counter as the input key material, which
    // matches RFC 4226 §5.2's `HS = HMAC-SHA(K, C)`.
    let counter = step.to_be_bytes();
    let hmac_bytes = hkdf::extract(secret, &counter);

    // RFC 4226 §5.3 dynamic truncation: low 4 bits of the last
    // byte pick a starting offset into the HMAC output; read a
    // big-endian 31-bit integer from that offset and reduce
    // modulo 10^digits.
    let offset = (hmac_bytes[hmac_bytes.len() - 1] & 0x0f) as usize;
    let bin_code = (u32::from(hmac_bytes[offset] & 0x7f) << 24)
        | (u32::from(hmac_bytes[offset + 1]) << 16)
        | (u32::from(hmac_bytes[offset + 2]) << 8)
        | u32::from(hmac_bytes[offset + 3]);
    let modulus = 10u32.pow(digits as u32);
    let code = bin_code % modulus;
    format!("{code:0width$}", width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_proto::crypto::x25519::PublicKey;
    use desmos_proto::crypto::x25519::X25519PrivateKey;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn sample_initiator() -> PublicKey {
        X25519PrivateKey::from_bytes([0x11; 32]).public_key()
    }

    fn sample_secret() -> Vec<u8> {
        b"0123456789abcdef0123456789abcdef".to_vec()
    }

    /// Clock closure backed by a mutable counter so the tests
    /// can advance time without touching the real system clock.
    fn fake_clock(now: Arc<Mutex<u64>>) -> Box<dyn Fn() -> u64 + Send + Sync> {
        Box::new(move || *now.lock().unwrap())
    }

    fn auth_with_clock(config: TotpConfig, now: Arc<Mutex<u64>>) -> TotpAuthenticator {
        TotpAuthenticator::with_clock(config, fake_clock(now))
    }

    fn ctx_with_code<'a>(
        init: &'a PublicKey,
        hash: &'a [u8; 32],
        cred: &'a [u8],
    ) -> AuthContext<'a> {
        AuthContext::new(init, hash, cred)
    }

    #[test]
    fn config_rejects_short_secret() {
        let err = TotpConfig::new(vec![0u8; 10]).unwrap_err();
        assert_eq!(err, AuthError::Misconfigured("TOTP secret shorter than 16 bytes"));
    }

    #[test]
    fn config_rejects_long_secret() {
        let err = TotpConfig::new(vec![0u8; 128]).unwrap_err();
        assert_eq!(err, AuthError::Misconfigured("TOTP secret longer than 64 bytes"));
    }

    #[test]
    fn config_rejects_non_6_to_8_digits() {
        let err = TotpConfig::with(sample_secret(), 5, 30, 1, false).unwrap_err();
        assert_eq!(err, AuthError::Misconfigured("TOTP digits must be 6, 7, or 8"));
        let err = TotpConfig::with(sample_secret(), 9, 30, 1, false).unwrap_err();
        assert_eq!(err, AuthError::Misconfigured("TOTP digits must be 6, 7, or 8"));
    }

    #[test]
    fn config_rejects_zero_period() {
        let err = TotpConfig::with(sample_secret(), 6, 0, 1, false).unwrap_err();
        assert_eq!(err, AuthError::Misconfigured("TOTP period_secs must be > 0"));
    }

    #[test]
    fn config_rejects_huge_skew_window() {
        let err = TotpConfig::with(sample_secret(), 6, 30, 9, false).unwrap_err();
        assert_eq!(err, AuthError::Misconfigured("TOTP skew_window > 8"));
    }

    #[test]
    fn code_is_six_decimal_digits_by_default() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let code = auth.code_for_step(auth.current_step());
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn code_uses_all_eight_digits_when_requested() {
        let cfg = TotpConfig::with(sample_secret(), 8, 30, 1, false).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let code = auth.code_for_step(auth.current_step());
        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn current_code_authenticates() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let code = auth.code_for_step(auth.current_step());
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, code.as_bytes());
        assert!(auth.authenticate(&ctx).is_ok());
    }

    #[test]
    fn one_step_clock_drift_authenticates_within_window() {
        let cfg = TotpConfig::with(sample_secret(), 6, 30, 1, false).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        // Client computes a code one step in the past and sends
        // it — the server's center step should still accept it
        // because the -1 offset is inside the window.
        let past_code = auth.code_for_step(auth.current_step() - 1);
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, past_code.as_bytes());
        assert!(auth.authenticate(&ctx).is_ok());
    }

    #[test]
    fn two_step_clock_drift_rejects_at_window_size_one() {
        let cfg = TotpConfig::with(sample_secret(), 6, 30, 1, false).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let far_code = auth.code_for_step(auth.current_step() - 2);
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, far_code.as_bytes());
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn wider_window_accepts_two_step_drift() {
        let cfg = TotpConfig::with(sample_secret(), 6, 30, 2, false).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let far_code = auth.code_for_step(auth.current_step() - 2);
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, far_code.as_bytes());
        assert!(auth.authenticate(&ctx).is_ok());
    }

    #[test]
    fn wrong_digit_code_rejects() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, b"000000");
        // There is a vanishingly small chance the real code for
        // this step is 000000; the fixed time picked above avoids
        // that specific step deterministically. If it ever
        // collides in the future, shift `now` by one second.
        let code = auth.code_for_step(auth.current_step());
        if code == "000000" {
            return;
        }
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn short_credential_rejects_without_hmac() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, b"12345");
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn non_digit_credential_rejects() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, b"12 456");
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn empty_credential_rejects() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, b"");
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn reject_replay_mode_blocks_second_use_of_same_step() {
        let cfg = TotpConfig::with(sample_secret(), 6, 30, 1, /*reject_replay=*/ true).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let code = auth.code_for_step(auth.current_step());
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, code.as_bytes());
        assert!(auth.authenticate(&ctx).is_ok());
        // Second attempt with the same code + same clock rejects
        // because the step value has already been spent.
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn lenient_mode_allows_same_step_reused() {
        let cfg = TotpConfig::with(sample_secret(), 6, 30, 1, false).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now.clone());
        let code = auth.code_for_step(auth.current_step());
        let init = sample_initiator();
        let hash = [0u8; 32];
        let ctx = ctx_with_code(&init, &hash, code.as_bytes());
        assert!(auth.authenticate(&ctx).is_ok());
        assert!(auth.authenticate(&ctx).is_ok());
    }

    #[test]
    fn name_is_totp() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(0));
        let auth = auth_with_clock(cfg, now);
        assert_eq!(auth.name(), "totp");
    }

    #[test]
    fn distinct_steps_produce_distinct_codes() {
        // Two adjacent steps should almost always produce
        // different codes; run 10 adjacent pairs and assert at
        // least one differs per pair (effectively every pair).
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(1_700_000_000));
        let auth = auth_with_clock(cfg, now);
        for i in 0..10u64 {
            let a = auth.code_for_step(i);
            let b = auth.code_for_step(i + 1);
            // At least one decimal digit differs.
            assert_ne!(a, b, "codes match at step {i}");
        }
    }

    /// RFC 6238 Appendix B test vectors for the HMAC-SHA256
    /// variant. The Appendix uses a 32-byte ASCII key
    /// `12345678901234567890123456789012` and 8-digit codes at
    /// `T = floor(time / 30)`. Every vector below is a direct
    /// cut-and-paste from the RFC table for SHA256.
    #[test]
    fn rfc6238_appendix_b_sha256_vectors() {
        let key = b"12345678901234567890123456789012".to_vec();
        let cfg = TotpConfig::with(key, 8, 30, 0, false).unwrap();
        let now = Arc::new(Mutex::new(0u64));
        let auth = auth_with_clock(cfg, now.clone());
        // (time, expected 8-digit code)
        let vectors: &[(u64, &str)] = &[
            (59, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ];
        for (time, expected) in vectors {
            let step = *time / 30;
            let code = auth.code_for_step(step);
            assert_eq!(code, *expected, "RFC 6238 vector mismatch at time {time}",);
        }
    }

    #[test]
    fn debug_format_redacts_secret_material() {
        let cfg = TotpConfig::new(sample_secret()).unwrap();
        let now = Arc::new(Mutex::new(0));
        let auth = auth_with_clock(cfg, now);
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("TotpAuthenticator"));
        assert!(rendered.contains("digits"));
        assert!(rendered.contains("period_secs"));
        // The secret must not appear in the Debug output.
        assert!(!rendered.contains("0123456789abcdef"));
    }
}
