//! Deterministic roundtrip fuzzer for the TOML parser.
//!
//! Generates 1000 random `Value` trees with a seeded linear-congruential
//! generator (so failures are reproducible without external dependencies),
//! renders each to TOML, parses it back, and asserts equality.
//!
//! `proptest` is the standard tool for this, but its transitive dependency
//! chain requires Rust edition 2024 (via `getrandom 0.4.x`), which is
//! incompatible with the project's pinned MSRV of 1.75.0. Until the MSRV
//! moves, we hand-roll the generator. This is consistent with the
//! project-wide "hand-rolled everything else" policy.

use std::collections::BTreeMap;

use desmos_core::config::parse;
use desmos_core::config::to_toml;
use desmos_core::config::Value;

/// xorshift64 — deterministic, no external dependency.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 0xdead_beef_cafe_babe } else { seed } }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        let span = hi - lo;
        lo + (self.next_u64() as usize) % span
    }

    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }

    fn ident(&mut self) -> String {
        // `[k-z][a-z0-9_]{3,8}` — avoids collision with `true` / `false`
        // (both start with letters outside the k-z range).
        let len = self.range(4, 8);
        let mut s = String::with_capacity(len);
        s.push(char::from(b'k' + (self.next_u64() % 16) as u8));
        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789_";
        for _ in 1..len {
            let idx = (self.next_u64() as usize) % alphabet.len();
            s.push(alphabet[idx] as char);
        }
        s
    }

    fn ascii_string(&mut self) -> String {
        let len = self.range(0, 16);
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
        (0..len).map(|_| alphabet[(self.next_u64() as usize) % alphabet.len()] as char).collect()
    }
}

fn gen_scalar(rng: &mut Rng) -> Value {
    match rng.range(0, 3) {
        0 => Value::String(rng.ascii_string()),
        1 => Value::Integer((rng.next_u64() as i64) >> 1),
        _ => Value::Boolean(rng.bool()),
    }
}

fn gen_primitive_array(rng: &mut Rng) -> Value {
    let len = rng.range(1, 5);
    let mut items = Vec::with_capacity(len);
    // Homogeneous arrays only.
    let variant = rng.range(0, 3);
    for _ in 0..len {
        let v = match variant {
            0 => Value::String(rng.ascii_string()),
            1 => Value::Integer((rng.next_u64() as i64) >> 1),
            _ => Value::Boolean(rng.bool()),
        };
        items.push(v);
    }
    Value::Array(items)
}

fn gen_leaf(rng: &mut Rng) -> Value {
    if rng.range(0, 4) == 0 {
        gen_primitive_array(rng)
    } else {
        gen_scalar(rng)
    }
}

fn gen_section(rng: &mut Rng) -> Value {
    let n = rng.range(1, 6);
    let mut table = BTreeMap::new();
    for _ in 0..n {
        let key = rng.ident();
        if table.contains_key(&key) {
            continue;
        }
        table.insert(key, gen_leaf(rng));
    }
    if table.is_empty() {
        table.insert("fallback".to_string(), Value::Integer(0));
    }
    Value::Table(table)
}

fn gen_config(rng: &mut Rng) -> Value {
    let n = rng.range(1, 5);
    let mut root = BTreeMap::new();
    for _ in 0..n {
        let key = rng.ident();
        if root.contains_key(&key) {
            continue;
        }
        root.insert(key, gen_section(rng));
    }
    if root.is_empty() {
        root.insert("fallback".to_string(), gen_section(rng));
    }
    Value::Table(root)
}

#[test]
fn roundtrip_1000_cases() {
    let mut rng = Rng::new(0x1234_5678_abcd_ef01);
    for case in 0..1000 {
        let v = gen_config(&mut rng);
        let rendered = to_toml(&v);
        match parse(&rendered) {
            Ok(parsed) => {
                assert_eq!(
                    parsed, v,
                    "roundtrip mismatch on case {case}:\n--- rendered ---\n{rendered}"
                );
            }
            Err(e) => {
                panic!("parse failed on case {case}: {e}\n--- rendered ---\n{rendered}");
            }
        }
    }
}

#[test]
fn whitespace_only_input_yields_empty_table() {
    for n in 0..20 {
        let src = "\n".repeat(n);
        let v = parse(&src).unwrap();
        assert_eq!(v, Value::Table(BTreeMap::new()));
    }
}
