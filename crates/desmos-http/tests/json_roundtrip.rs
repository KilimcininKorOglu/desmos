//! Deterministic JSON roundtrip fuzzer (1000 random trees).
//!
//! Uses a seeded xorshift64 PRNG instead of proptest (blocked by
//! MSRV 1.75.0 — see MEMORY.md dependency landmines).

use desmos_http::json::{decode, encode, Value};
use std::collections::BTreeMap;

// ---- xorshift64 PRNG --------------------------------------------------------

struct Xorshift64(u64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Random u64 in [0, bound).
    fn next_bound(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    /// Random bool.
    fn next_bool(&mut self) -> bool {
        self.next() & 1 == 0
    }

    /// Random f64 in a safe range (no NaN/Infinity).
    fn next_f64(&mut self) -> f64 {
        let raw = self.next();
        let sign = if raw & 1 == 0 { 1.0 } else { -1.0 };
        let int_part = (raw >> 16) % 100_000;
        let frac = (raw >> 32) % 1000;
        sign * (int_part as f64 + frac as f64 / 1000.0)
    }

    /// Random ASCII string (length 0..16).
    fn next_string(&mut self) -> String {
        let len = self.next_bound(16) as usize;
        (0..len)
            .map(|_| {
                let b = 0x20 + (self.next_bound(95) as u8); // printable ASCII
                                                            // Avoid backslash and quote to keep things simple.
                if b == b'\\' || b == b'"' {
                    'x'
                } else {
                    b as char
                }
            })
            .collect()
    }
}

// ---- Random value generator -------------------------------------------------

fn random_value(rng: &mut Xorshift64, depth: usize) -> Value {
    if depth > 6 {
        // At depth limit, return a leaf.
        return match rng.next_bound(4) {
            0 => Value::Null,
            1 => Value::Bool(rng.next_bool()),
            2 => Value::Number(rng.next_f64()),
            _ => Value::String(rng.next_string()),
        };
    }

    match rng.next_bound(7) {
        0 => Value::Null,
        1 => Value::Bool(rng.next_bool()),
        2 => Value::Number(rng.next_f64()),
        3 => Value::String(rng.next_string()),
        4 => {
            // Array (0..5 elements).
            let len = rng.next_bound(5) as usize;
            let arr: Vec<Value> = (0..len).map(|_| random_value(rng, depth + 1)).collect();
            Value::Array(arr)
        }
        5 | 6 => {
            // Object (0..4 keys).
            let len = rng.next_bound(4) as usize;
            let mut obj = BTreeMap::new();
            for _ in 0..len {
                let key = format!("k{}", rng.next_bound(100));
                obj.insert(key, random_value(rng, depth + 1));
            }
            Value::Object(obj)
        }
        _ => unreachable!(),
    }
}

// ---- Test -------------------------------------------------------------------

#[test]
fn roundtrip_1000_random_trees() {
    let mut rng = Xorshift64(0xDE50_0500_DEAD_BEEF);
    let mut failures = 0;

    for i in 0..1000 {
        let original = random_value(&mut rng, 0);
        let json_str = encode(&original);

        let decoded = match decode(&json_str) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[{i}] decode failed: {e}\n  json: {json_str}");
                failures += 1;
                continue;
            }
        };

        if original != decoded {
            eprintln!("[{i}] roundtrip mismatch");
            eprintln!("  original: {original:?}");
            eprintln!("  decoded:  {decoded:?}");
            eprintln!("  json:     {json_str}");
            failures += 1;
        }
    }

    assert_eq!(failures, 0, "{failures} roundtrip failures out of 1000");
}
