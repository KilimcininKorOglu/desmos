//! Anti-replay fuzzer: 10 000 deterministic random streams cross-check
//! `AntiReplayWindow` against a reference model that tracks every seen
//! sequence number plus the current window tail.
//!
//! The acceptance criterion for Task 18 is "no false accepts across 10k
//! random streams"; we assert the stronger property that every accept /
//! reject decision matches the reference exactly.
//!
//! `proptest` is still blocked on MSRV 1.75 so this uses the same
//! xorshift64 pattern the rest of the workspace already uses.

use std::collections::HashSet;

use desmos_proto::antireplay::AntiReplayWindow;
use desmos_proto::antireplay::ReplayError;
use desmos_proto::antireplay::WINDOW_SIZE;

/// Reference implementation: a set of seen sequence numbers plus the
/// highest one accepted so far. Pruned down to within-window entries
/// after every accept so lookups stay O(1) and the set never grows.
struct Reference {
    seen: HashSet<u64>,
    highest: Option<u64>,
}

impl Reference {
    fn new() -> Self {
        Self { seen: HashSet::new(), highest: None }
    }

    /// Mirrors `AntiReplayWindow::check_and_update` exactly.
    fn check_and_update(&mut self, seq: u64) -> Result<(), ReplayError> {
        if let Some(h) = self.highest {
            if seq + WINDOW_SIZE <= h {
                return Err(ReplayError::OutOfWindow);
            }
        }
        if self.seen.contains(&seq) {
            return Err(ReplayError::Duplicate);
        }
        self.seen.insert(seq);
        if self.highest.map_or(true, |h| seq > h) {
            self.highest = Some(seq);
        }
        if let Some(h) = self.highest {
            self.seen.retain(|&s| s + WINDOW_SIZE > h);
        }
        Ok(())
    }
}

/// Tiny xorshift64 RNG. Seeded deterministically so every run produces
/// identical streams.
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

/// Drive one random stream through both the real window and the
/// reference, asserting every decision matches. Returns `(accepts,
/// rejects)` so the caller can sanity-check both outcomes are exercised.
fn fuzz_one_stream(seed: u64, packets: usize) -> (usize, usize) {
    let mut rng = Xorshift64::new(seed);
    let mut real = AntiReplayWindow::new();
    let mut reference = Reference::new();
    let mut accepts = 0;
    let mut rejects = 0;

    // Start every stream near 200 so both "in window" and
    // "out of window" branches are reachable from the first packet.
    let mut cursor: u64 = 200;

    for _ in 0..packets {
        let choice = rng.next_u64() % 10;
        let seq = match choice {
            0..=4 => {
                // 50%: near the cursor (in window, usually fresh).
                let off = rng.next_u64() % (WINDOW_SIZE * 2);
                cursor.saturating_add(off).saturating_sub(WINDOW_SIZE)
            }
            5..=6 => {
                // 20%: a recent seq, often a duplicate.
                let off = rng.next_u64() % WINDOW_SIZE;
                cursor.saturating_sub(off)
            }
            7 => {
                // 10%: big forward jump.
                cursor.saturating_add(1_000 + (rng.next_u64() % 5_000))
            }
            8 => {
                // 10%: ancient seq that should be out of window.
                let far = rng.next_u64() % 10_000;
                cursor.saturating_sub(far.saturating_add(WINDOW_SIZE * 2))
            }
            9 => {
                // 10%: exactly the cursor, guaranteed duplicate after
                // the first hit.
                cursor
            }
            _ => unreachable!(),
        };

        let expected = reference.check_and_update(seq);
        let actual = real.check_and_update(seq);
        assert_eq!(
            actual, expected,
            "stream seed {seed}, seq {seq}: real {actual:?} != reference {expected:?}"
        );

        if actual.is_ok() {
            accepts += 1;
            if seq > cursor {
                cursor = seq;
            }
        } else {
            rejects += 1;
        }
    }
    (accepts, rejects)
}

#[test]
fn fuzz_10000_random_streams_no_false_decisions() {
    let mut total_accepts = 0usize;
    let mut total_rejects = 0usize;
    for stream in 0..10_000u64 {
        // Derive a per-stream seed from a high-entropy base so adjacent
        // streams do not produce near-identical sequences.
        let seed =
            0xDE50_0700_0000_0000u64.wrapping_add(stream.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let (a, r) = fuzz_one_stream(seed, 64);
        total_accepts += a;
        total_rejects += r;
    }
    assert!(total_accepts > 0, "fuzz never accepted anything — RNG bug?");
    assert!(total_rejects > 0, "fuzz never rejected anything — window bug?");
}

#[test]
fn reference_and_real_agree_on_in_order_stream() {
    let mut real = AntiReplayWindow::new();
    let mut reference = Reference::new();
    for seq in 0..1_000u64 {
        assert_eq!(real.check_and_update(seq), reference.check_and_update(seq));
    }
}

#[test]
fn reference_and_real_agree_on_reverse_order_stream() {
    let mut real = AntiReplayWindow::new();
    let mut reference = Reference::new();
    // Start at 500 so everything below stays inside the window once we
    // reach the first accept.
    for seq in (500 - (WINDOW_SIZE - 1)..=500).rev() {
        assert_eq!(real.check_and_update(seq), reference.check_and_update(seq));
    }
}

#[test]
fn reference_and_real_agree_on_pathological_stream() {
    // Hit every branch: fresh forward, out-of-order in window, old
    // duplicate, big jump, exact window boundary.
    let stream: &[u64] = &[100, 101, 99, 98, 100, 105, 1_000_000, 100, 999_873, 999_872];
    let mut real = AntiReplayWindow::new();
    let mut reference = Reference::new();
    for &seq in stream {
        assert_eq!(
            real.check_and_update(seq),
            reference.check_and_update(seq),
            "mismatch on seq {seq}",
        );
    }
}
