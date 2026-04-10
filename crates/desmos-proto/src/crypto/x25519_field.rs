//! Hand-rolled X25519 scalar multiplication (RFC 7748 §5).
//!
//! Ported from the public-domain TweetNaCl reference implementation by
//! Bernstein, Janssen, Lange, and Schwabe (https://tweetnacl.cr.yp.to).
//! The field representation is 16 signed 64-bit limbs of radix 16 —
//! slower than a 5-limb radix-51 layout but dramatically simpler. Desmos
//! runs X25519 once per handshake, so the few extra nanoseconds do not
//! matter.
//!
//! # Why hand-rolled
//!
//! `ring::agreement::EphemeralPrivateKey::diffie_hellman` is move-consuming
//! and `ring::rand::SecureRandom` is a sealed trait, so ring cannot expose
//! a reusable X25519 private key. Noise IK needs the initiator's ephemeral
//! and static keys to run two DH operations each, so we ship our own
//! scalarmult. Correctness is verified by cross-checking every DH result
//! against `ring::agreement` (see `cross_check_fifty_rounds_against_ring`).
//!
//! # Constant-time
//!
//! The Montgomery ladder processes the scalar bit-by-bit using
//! `constant_time_swap`; no branch depends on secret bits. Every field
//! operation is a fixed sequence of adds / subs / muls, independent of
//! input values. The scalarmult function is safe to call with secret
//! scalars.

/// Field element in GF(2^255 - 19), 16 signed limbs of radix 16.
type Fe = [i64; 16];

const ZERO: Fe = [0; 16];

/// The constant 121665, used by the Montgomery ladder step for curve
/// parameter `a24 = (a+2)/4 = 121665`.
const GF_121665: Fe = {
    let mut f = [0i64; 16];
    f[0] = 0xDB41;
    f[1] = 1;
    f
};

/// Carry-propagate once through all limbs, wrapping the top limb's
/// overflow back into limb 0 with a factor of 38 (since `2^256 ≡ 38
/// mod p`, where `p = 2^255 - 19`).
fn carry(o: &mut Fe) {
    for i in 0..16 {
        o[i] = o[i].wrapping_add(1i64 << 16);
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] = o[i + 1].wrapping_add(c - 1);
        } else {
            // Last limb: the carry wraps with the extra 37*(c-1) correction
            // so the total added to limb 0 is 38*(c-1) per the 2^256
            // reduction.
            o[0] = o[0].wrapping_add(38 * (c - 1));
        }
        o[i] = o[i].wrapping_sub(c << 16);
    }
}

/// Constant-time swap of `p` and `q` iff `b == 1`.
fn constant_time_swap(p: &mut Fe, q: &mut Fe, b: i64) {
    let c = !(b.wrapping_sub(1));
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/// Canonicalise `n` (fully reduce mod p) and serialise to little-endian.
fn pack(o: &mut [u8; 32], n: &Fe) {
    let mut t: Fe = *n;
    carry(&mut t);
    carry(&mut t);
    carry(&mut t);
    // Two rounds of conditional subtraction to bring t into [0, p).
    for _ in 0..2 {
        let mut m: Fe = ZERO;
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        // If b == 0 (t >= p) swap t <- m, else keep t.
        constant_time_swap(&mut t, &mut m, 1 - b);
    }
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
}

/// Deserialise a little-endian 32-byte u-coordinate into a field element.
/// The top bit of the last byte is ignored per RFC 7748 §5.
fn unpack(o: &mut Fe, n: &[u8; 32]) {
    for i in 0..16 {
        o[i] = (n[2 * i] as i64) + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
}

fn fadd(o: &mut Fe, a: &Fe, b: &Fe) {
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
}

fn fsub(o: &mut Fe, a: &Fe, b: &Fe) {
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
}

fn fmul(o: &mut Fe, a: &Fe, b: &Fe) {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    o[..16].copy_from_slice(&t[..16]);
    carry(o);
    carry(o);
}

fn fsqr(o: &mut Fe, a: &Fe) {
    let copy = *a;
    fmul(o, &copy, &copy);
}

/// Field inversion via Fermat's little theorem: `a^(p-2) = a^(2^255-21)`.
fn finv(o: &mut Fe, i: &Fe) {
    let mut c: Fe = *i;
    for a in (0..=253).rev() {
        let tmp = c;
        fsqr(&mut c, &tmp);
        if a != 2 && a != 4 {
            let tmp2 = c;
            fmul(&mut c, &tmp2, i);
        }
    }
    *o = c;
}

/// X25519 scalar multiplication: `q = scalarmult(n, p)` where `n` is the
/// scalar and `p` is the input u-coordinate.
///
/// This is the core primitive from RFC 7748 §5. The scalar is clamped
/// inline per §5: bits 0..2 cleared, bit 254 set, bit 255 cleared.
pub fn scalarmult(q: &mut [u8; 32], n: &[u8; 32], p: &[u8; 32]) {
    // Clamp the scalar into a new buffer so we do not mutate the caller's
    // private key.
    let mut z = [0u8; 32];
    z[..31].copy_from_slice(&n[..31]);
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;

    let mut x: Fe = ZERO;
    unpack(&mut x, p);

    let mut a: Fe = ZERO;
    let mut b: Fe = x;
    let mut c: Fe = ZERO;
    let mut d: Fe = ZERO;
    a[0] = 1;
    d[0] = 1;

    let mut e: Fe = ZERO;
    let mut f: Fe = ZERO;

    for i in (0..=254).rev() {
        let r: i64 = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        constant_time_swap(&mut a, &mut b, r);
        constant_time_swap(&mut c, &mut d, r);

        fadd(&mut e, &a, &c);
        let ta = a;
        fsub(&mut a, &ta, &c);
        fadd(&mut c, &b, &d);
        let tb = b;
        fsub(&mut b, &tb, &d);
        fsqr(&mut d, &e);
        fsqr(&mut f, &a);
        let ta = a;
        fmul(&mut a, &c, &ta);
        let tb = b;
        let te = e;
        fmul(&mut c, &tb, &te);
        let ta = a;
        let tc = c;
        fadd(&mut e, &ta, &tc);
        fsub(&mut a, &ta, &tc);
        let ta = a;
        fsqr(&mut b, &ta);
        let td = d;
        fsub(&mut c, &td, &f);
        let tc = c;
        fmul(&mut a, &tc, &GF_121665);
        let ta = a;
        let td = d;
        fadd(&mut a, &ta, &td);
        let tc = c;
        let ta = a;
        fmul(&mut c, &tc, &ta);
        let td = d;
        let tf = f;
        fmul(&mut a, &td, &tf);
        let tb = b;
        fmul(&mut d, &tb, &x);
        let te = e;
        fsqr(&mut b, &te);

        constant_time_swap(&mut a, &mut b, r);
        constant_time_swap(&mut c, &mut d, r);
    }

    // Invert c and multiply with a to project from (X:Z) back to x.
    let mut inv_c: Fe = ZERO;
    finv(&mut inv_c, &c);
    let mut result: Fe = ZERO;
    fmul(&mut result, &a, &inv_c);
    pack(q, &result);
}

/// Convenience: scalarmult with the Curve25519 basepoint (u = 9).
pub fn scalarmult_base(q: &mut [u8; 32], n: &[u8; 32]) {
    let mut base = [0u8; 32];
    base[0] = 9;
    scalarmult(q, n, &base);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "hex32 expects 64 chars");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// RFC 7748 §5.2 test vector 1.
    #[test]
    fn rfc7748_vector_1() {
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u_in = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let mut out = [0u8; 32];
        scalarmult(&mut out, &scalar, &u_in);
        assert_eq!(out, expected);
    }

    /// RFC 7748 §5.2 test vector 2.
    #[test]
    fn rfc7748_vector_2() {
        let scalar = hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u_in = hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        let mut out = [0u8; 32];
        scalarmult(&mut out, &scalar, &u_in);
        assert_eq!(out, expected);
    }

    /// RFC 7748 §5.2 1-iteration test: start with k = u = 9, compute
    /// `k = X25519(k, u)` once.
    #[test]
    fn rfc7748_iterated_once() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let u = k;
        let expected = hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        let mut result = [0u8; 32];
        scalarmult(&mut result, &k, &u);
        assert_eq!(result, expected);
    }

    #[test]
    fn finv_is_multiplicative_inverse() {
        let x: Fe = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut inv = ZERO;
        finv(&mut inv, &x);
        let mut product = ZERO;
        fmul(&mut product, &x, &inv);
        let mut bytes = [0u8; 32];
        pack(&mut bytes, &product);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(bytes, expected);
    }

    #[test]
    fn fmul_then_pack_is_canonical_small() {
        let x: Fe = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let y: Fe = [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut p = ZERO;
        fmul(&mut p, &x, &y);
        let mut bytes = [0u8; 32];
        pack(&mut bytes, &p);
        let mut expected = [0u8; 32];
        expected[0] = 35;
        assert_eq!(bytes, expected);
    }

    /// The real correctness guarantee: cross-check against ring's
    /// X25519 implementation across many random rounds. If the
    /// hand-rolled scalarmult disagrees with ring on any pair, this
    /// test catches it. We went hand-rolled because ring cannot expose
    /// a persistent private key, not because we doubted ring's
    /// correctness — ring is our ground truth here.
    #[test]
    fn cross_check_fifty_rounds_against_ring() {
        use ring::agreement;
        use ring::rand::SecureRandom;
        use ring::rand::SystemRandom;

        let rng = SystemRandom::new();

        for _ in 0..50 {
            let mut my_priv = [0u8; 32];
            rng.fill(&mut my_priv).unwrap();
            let mut my_pub = [0u8; 32];
            scalarmult_base(&mut my_pub, &my_priv);

            let ring_eph =
                agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
            let ring_pub = ring_eph.compute_public_key().unwrap();
            let mut ring_pub_bytes = [0u8; 32];
            ring_pub_bytes.copy_from_slice(ring_pub.as_ref());

            let mut shared_via_me = [0u8; 32];
            scalarmult(&mut shared_via_me, &my_priv, &ring_pub_bytes);

            let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, my_pub);
            let shared_via_ring: [u8; 32] = agreement::agree_ephemeral(ring_eph, &peer, |s| {
                let mut out = [0u8; 32];
                out.copy_from_slice(s);
                out
            })
            .unwrap();

            assert_eq!(
                shared_via_me, shared_via_ring,
                "hand-rolled scalarmult disagrees with ring"
            );
        }
    }
}
