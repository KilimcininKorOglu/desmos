//! Hierarchical timer wheel for keepalives, probes, and rekey.
//!
//! Four levels × 32 slots give O(1) schedule and amortised O(1) poll per
//! expired timer. Slot durations double-up in powers of 32:
//!
//! | Level | Slot duration | Range         |
//! |------:|:--------------|:--------------|
//! | 0     | 1 ms          | 32 ms         |
//! | 1     | 32 ms         | 1 024 ms      |
//! | 2     | 1 024 ms      | ~32 s         |
//! | 3     | 32 768 ms     | ~17.5 min     |
//!
//! Timers with a delay outside the total range wrap around level 3 multiple
//! times until they settle into a lower level. The practical Desmos timers
//! (keepalive 25 s, probe 500 ms, rekey 120 s) all fit comfortably inside
//! level 2 so the cascade cost is cheap.

use core::array::from_fn;

pub type TimerId = u64;

const NUM_LEVELS: usize = 4;
const SLOTS: usize = 32;
const SLOT_MASK: u64 = (SLOTS as u64) - 1;
const BITS_PER_LEVEL: u32 = 5;
/// Total span (ms) the wheel can schedule into before wrap-around.
pub const WHEEL_RANGE_MS: u64 = 1u64 << (BITS_PER_LEVEL * NUM_LEVELS as u32);

#[derive(Debug, Clone, Copy)]
struct Entry {
    id: TimerId,
    expires_at_ms: u64,
}

/// A fired timer, returned from [`TimerWheel::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiredTimer {
    pub id: TimerId,
    pub expires_at_ms: u64,
}

pub struct TimerWheel {
    levels: [[Vec<Entry>; SLOTS]; NUM_LEVELS],
    current_ms: u64,
    next_id: u64,
}

impl TimerWheel {
    pub fn new(start_ms: u64) -> Self {
        let levels = from_fn(|_| from_fn(|_| Vec::<Entry>::new()));
        Self { levels, current_ms: start_ms, next_id: 0 }
    }

    /// Current wheel time in milliseconds.
    pub fn now_ms(&self) -> u64 {
        self.current_ms
    }

    /// Schedule a timer to fire `after_ms` milliseconds from now. Returns a
    /// fresh [`TimerId`]. Delays larger than the wheel range are accepted
    /// and simply cascade through the top level until they fit.
    pub fn schedule(&mut self, after_ms: u64) -> TimerId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let expires_at_ms = self.current_ms.saturating_add(after_ms);
        self.insert_entry(Entry { id, expires_at_ms });
        id
    }

    /// Advance the wheel to `now_ms` and push every expired timer into
    /// `out`. `now_ms` must be `>= now_ms()`; calling with an earlier
    /// timestamp is a no-op.
    pub fn poll(&mut self, now_ms: u64, out: &mut Vec<FiredTimer>) {
        while self.current_ms <= now_ms {
            self.cascade_if_needed();
            let l0_idx = (self.current_ms & SLOT_MASK) as usize;
            // Take ownership of the slot so re-inserts during fire do not
            // walk their way back in.
            let slot = core::mem::take(&mut self.levels[0][l0_idx]);
            for entry in slot {
                out.push(FiredTimer { id: entry.id, expires_at_ms: entry.expires_at_ms });
            }
            self.current_ms = match self.current_ms.checked_add(1) {
                Some(v) => v,
                None => return,
            };
        }
    }

    fn insert_entry(&mut self, entry: Entry) {
        let delta = entry.expires_at_ms.saturating_sub(self.current_ms);
        let lvl = level_for_delta(delta);
        let slot_bits = lvl as u32 * BITS_PER_LEVEL;
        let slot_idx = ((entry.expires_at_ms >> slot_bits) & SLOT_MASK) as usize;
        self.levels[lvl][slot_idx].push(entry);
    }

    fn cascade_if_needed(&mut self) {
        // Cascade from high levels to low so timers that are moved into a
        // higher-resolution slot during this tick are still reachable from
        // the lower-level cascade below it.
        if self.current_ms & ((1u64 << (3 * BITS_PER_LEVEL)) - 1) == 0 {
            self.cascade_level(3);
        }
        if self.current_ms & ((1u64 << (2 * BITS_PER_LEVEL)) - 1) == 0 {
            self.cascade_level(2);
        }
        if self.current_ms & SLOT_MASK == 0 {
            self.cascade_level(1);
        }
    }

    fn cascade_level(&mut self, lvl: usize) {
        if lvl >= NUM_LEVELS {
            return;
        }
        let slot_bits = lvl as u32 * BITS_PER_LEVEL;
        let slot_idx = ((self.current_ms >> slot_bits) & SLOT_MASK) as usize;
        let entries = core::mem::take(&mut self.levels[lvl][slot_idx]);
        for e in entries {
            self.insert_entry(e);
        }
    }
}

fn level_for_delta(delta: u64) -> usize {
    if delta < (1u64 << BITS_PER_LEVEL) {
        0
    } else if delta < (1u64 << (2 * BITS_PER_LEVEL)) {
        1
    } else if delta < (1u64 << (3 * BITS_PER_LEVEL)) {
        2
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_ids(out: &[FiredTimer]) -> Vec<TimerId> {
        out.iter().map(|e| e.id).collect()
    }

    #[test]
    fn schedule_zero_fires_on_same_tick() {
        let mut w = TimerWheel::new(0);
        let id = w.schedule(0);
        let mut out = Vec::new();
        w.poll(0, &mut out);
        assert_eq!(collect_ids(&out), vec![id]);
    }

    #[test]
    fn schedule_within_level_zero() {
        let mut w = TimerWheel::new(0);
        let a = w.schedule(5);
        let b = w.schedule(10);
        let c = w.schedule(31);
        let mut out = Vec::new();
        w.poll(31, &mut out);
        let ids: Vec<_> = collect_ids(&out);
        assert!(ids.contains(&a));
        assert!(ids.contains(&b));
        assert!(ids.contains(&c));
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn cascade_level_one_into_level_zero() {
        let mut w = TimerWheel::new(0);
        // 50ms delay lives in L1 initially, should cascade at current_ms=32.
        let id = w.schedule(50);
        let mut out = Vec::new();
        // Advance past the cascade boundary but not past the firing time.
        w.poll(49, &mut out);
        assert!(out.is_empty(), "timer should not have fired yet");
        // Now advance to the firing tick.
        w.poll(50, &mut out);
        assert_eq!(collect_ids(&out), vec![id]);
    }

    #[test]
    fn cascade_level_two_into_level_one() {
        let mut w = TimerWheel::new(0);
        // 2000ms delay lives in L2 initially.
        let id = w.schedule(2000);
        let mut out = Vec::new();
        w.poll(1999, &mut out);
        assert!(out.is_empty());
        w.poll(2000, &mut out);
        assert_eq!(collect_ids(&out), vec![id]);
    }

    #[test]
    fn cascade_level_three_into_level_two() {
        let mut w = TimerWheel::new(0);
        // 40000ms delay lives in L3 initially.
        let id = w.schedule(40_000);
        let mut out = Vec::new();
        w.poll(39_999, &mut out);
        assert!(out.is_empty());
        w.poll(40_000, &mut out);
        assert_eq!(collect_ids(&out), vec![id]);
    }

    #[test]
    fn delays_beyond_range_eventually_fire() {
        let mut w = TimerWheel::new(0);
        // Twice the wheel range (2 * 2^20 ms = ~35 min)
        let long = 2 * WHEEL_RANGE_MS;
        let id = w.schedule(long);
        let mut out = Vec::new();
        w.poll(long - 1, &mut out);
        assert!(out.is_empty());
        w.poll(long, &mut out);
        assert_eq!(collect_ids(&out), vec![id]);
    }

    #[test]
    fn many_timers_within_one_second() {
        let mut w = TimerWheel::new(0);
        let mut expected: Vec<TimerId> = Vec::new();
        for i in 0..500u64 {
            let id = w.schedule(i * 2);
            expected.push(id);
        }
        let mut out = Vec::new();
        w.poll(1000, &mut out);
        let mut got: Vec<_> = collect_ids(&out);
        got.sort();
        expected.sort();
        assert_eq!(got, expected);
    }

    #[test]
    fn poll_with_past_now_is_noop() {
        let mut w = TimerWheel::new(100);
        let _ = w.schedule(10);
        let mut out = Vec::new();
        w.poll(50, &mut out); // before current_ms
        assert!(out.is_empty());
        assert_eq!(w.now_ms(), 100);
    }

    #[test]
    fn level_for_delta_boundaries() {
        assert_eq!(level_for_delta(0), 0);
        assert_eq!(level_for_delta(31), 0);
        assert_eq!(level_for_delta(32), 1);
        assert_eq!(level_for_delta(1023), 1);
        assert_eq!(level_for_delta(1024), 2);
        assert_eq!(level_for_delta(32_767), 2);
        assert_eq!(level_for_delta(32_768), 3);
        assert_eq!(level_for_delta(u64::MAX), 3);
    }
}
