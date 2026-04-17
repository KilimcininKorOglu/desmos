//! Hand-rolled JSON encoder and decoder.
//!
//! Supports a constrained subset sufficient for the Desmos Web UI
//! API:
//!
//! - **Values**: null, bool, number (f64, rejects NaN/Infinity),
//!   string (with `\uXXXX` escape), array, object.
//! - **Depth limit**: 32 levels max (prevents stack overflow on
//!   malicious input).
//! - **Numbers**: IEEE 754 finite doubles. Integer-valued doubles
//!   are serialized without a decimal point.
//!
//! No `serde` dependency — hand-rolled per the five-crate rule.

use std::collections::BTreeMap;
use std::fmt;

/// Maximum nesting depth for parsing.
const MAX_DEPTH: usize = 32;

// ---- Value type -------------------------------------------------------------

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// Check if the value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Get as bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as f64.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as string slice.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as array slice.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Get as object.
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Look up a key in an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        encode_value(self, f)
    }
}

// ---- Encoder ----------------------------------------------------------------

/// Encode a `Value` to a JSON string.
pub fn encode(value: &Value) -> String {
    value.to_string()
}

fn encode_value(value: &Value, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match value {
        Value::Null => f.write_str("null"),
        Value::Bool(true) => f.write_str("true"),
        Value::Bool(false) => f.write_str("false"),
        Value::Number(n) => {
            // Integer-valued doubles without decimal point.
            if n.fract() == 0.0 && n.abs() < (1i64 << 53) as f64 {
                write!(f, "{}", *n as i64)
            } else {
                write!(f, "{n}")
            }
        }
        Value::String(s) => encode_string(s, f),
        Value::Array(arr) => {
            f.write_str("[")?;
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }
                encode_value(v, f)?;
            }
            f.write_str("]")
        }
        Value::Object(obj) => {
            f.write_str("{")?;
            for (i, (k, v)) in obj.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }
                encode_string(k, f)?;
                f.write_str(":")?;
                encode_value(v, f)?;
            }
            f.write_str("}")
        }
    }
}

fn encode_string(s: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("\"")?;
    for ch in s.chars() {
        match ch {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if c < '\x20' => write!(f, "\\u{:04x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

// ---- Decoder ----------------------------------------------------------------

/// JSON parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// Unexpected end of input.
    UnexpectedEof,
    /// Unexpected character at the given position.
    UnexpectedChar(usize, char),
    /// Invalid number (NaN, Infinity, or malformed).
    InvalidNumber(usize),
    /// Unterminated string.
    UnterminatedString,
    /// Invalid escape sequence.
    InvalidEscape(usize),
    /// Nesting depth exceeded.
    DepthExceeded,
    /// Trailing content after the root value.
    TrailingContent(usize),
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::UnexpectedChar(pos, ch) => write!(f, "unexpected '{ch}' at position {pos}"),
            Self::InvalidNumber(pos) => write!(f, "invalid number at position {pos}"),
            Self::UnterminatedString => f.write_str("unterminated string"),
            Self::InvalidEscape(pos) => write!(f, "invalid escape at position {pos}"),
            Self::DepthExceeded => f.write_str("nesting depth exceeded (max 32)"),
            Self::TrailingContent(pos) => write!(f, "trailing content at position {pos}"),
        }
    }
}

/// Decode a JSON string into a `Value`.
pub fn decode(input: &str) -> Result<Value, JsonError> {
    let mut parser = Parser::new(input);
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.pos < parser.input.len() {
        return Err(JsonError::TrailingContent(parser.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input: input.as_bytes(), pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, expected: u8) -> Result<(), JsonError> {
        match self.advance() {
            Some(b) if b == expected => Ok(()),
            Some(b) => Err(JsonError::UnexpectedChar(self.pos - 1, b as char)),
            None => Err(JsonError::UnexpectedEof),
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            match self.input[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::DepthExceeded);
        }

        self.skip_whitespace();

        match self.peek() {
            None => Err(JsonError::UnexpectedEof),
            Some(b'"') => self.parse_string().map(Value::String),
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b't') => self.parse_literal(b"true", Value::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", Value::Bool(false)),
            Some(b'n') => self.parse_literal(b"null", Value::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(b) => Err(JsonError::UnexpectedChar(self.pos, b as char)),
        }
    }

    fn parse_literal(&mut self, expected: &[u8], value: Value) -> Result<Value, JsonError> {
        let start = self.pos;
        for &b in expected {
            match self.advance() {
                Some(actual) if actual == b => {}
                Some(actual) => {
                    return Err(JsonError::UnexpectedChar(self.pos - 1, actual as char))
                }
                None => return Err(JsonError::UnexpectedEof),
            }
        }
        let _ = start;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;

        // Optional minus.
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }

        // Integer part.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(JsonError::InvalidNumber(start)),
        }

        // Fractional part.
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::InvalidNumber(self.pos));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        // Exponent.
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::InvalidNumber(self.pos));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        let s = std::str::from_utf8(&self.input[start..self.pos]).unwrap();
        let n: f64 = s.parse().map_err(|_| JsonError::InvalidNumber(start))?;

        if n.is_nan() || n.is_infinite() {
            return Err(JsonError::InvalidNumber(start));
        }

        Ok(Value::Number(n))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut s = String::new();

        loop {
            match self.advance() {
                None => return Err(JsonError::UnterminatedString),
                Some(b'"') => return Ok(s),
                Some(b'\\') => {
                    let esc_pos = self.pos;
                    match self.advance() {
                        Some(b'"') => s.push('"'),
                        Some(b'\\') => s.push('\\'),
                        Some(b'/') => s.push('/'),
                        Some(b'n') => s.push('\n'),
                        Some(b'r') => s.push('\r'),
                        Some(b't') => s.push('\t'),
                        Some(b'b') => s.push('\u{0008}'),
                        Some(b'f') => s.push('\u{000C}'),
                        Some(b'u') => {
                            let cp = self.parse_hex4()?;
                            // Handle UTF-16 surrogate pairs.
                            if (0xD800..=0xDBFF).contains(&cp) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(JsonError::InvalidEscape(esc_pos));
                                }
                                let combined =
                                    0x10000 + ((cp as u32 - 0xD800) << 10) + (low as u32 - 0xDC00);
                                let ch = char::from_u32(combined)
                                    .ok_or(JsonError::InvalidEscape(esc_pos))?;
                                s.push(ch);
                            } else {
                                let ch = char::from_u32(cp as u32)
                                    .ok_or(JsonError::InvalidEscape(esc_pos))?;
                                s.push(ch);
                            }
                        }
                        _ => return Err(JsonError::InvalidEscape(esc_pos)),
                    }
                }
                Some(b) => s.push(b as char),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, JsonError> {
        let start = self.pos;
        let mut val: u16 = 0;
        for _ in 0..4 {
            let b = self.advance().ok_or(JsonError::UnexpectedEof)?;
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(JsonError::InvalidEscape(start)),
            };
            val = (val << 4) | digit as u16;
        }
        Ok(val)
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.expect(b'[')?;
        self.skip_whitespace();

        let mut arr = Vec::new();

        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(arr));
        }

        loop {
            let v = self.parse_value(depth + 1)?;
            arr.push(v);

            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(arr));
                }
                Some(b) => return Err(JsonError::UnexpectedChar(self.pos, b as char)),
                None => return Err(JsonError::UnexpectedEof),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.expect(b'{')?;
        self.skip_whitespace();

        let mut obj = BTreeMap::new();

        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(obj));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;

            self.skip_whitespace();
            self.expect(b':')?;

            let val = self.parse_value(depth + 1)?;
            obj.insert(key, val);

            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(obj));
                }
                Some(b) => return Err(JsonError::UnexpectedChar(self.pos, b as char)),
                None => return Err(JsonError::UnexpectedEof),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Encode tests ---------------------------------------------------

    #[test]
    fn encode_null() {
        assert_eq!(encode(&Value::Null), "null");
    }

    #[test]
    fn encode_bool() {
        assert_eq!(encode(&Value::Bool(true)), "true");
        assert_eq!(encode(&Value::Bool(false)), "false");
    }

    #[test]
    fn encode_integer_number() {
        assert_eq!(encode(&Value::Number(42.0)), "42");
        assert_eq!(encode(&Value::Number(-7.0)), "-7");
        assert_eq!(encode(&Value::Number(0.0)), "0");
    }

    #[test]
    fn encode_fractional_number() {
        let s = encode(&Value::Number(3.25));
        assert!(s.starts_with("3.25"));
    }

    #[test]
    fn encode_string_simple() {
        assert_eq!(encode(&Value::String("hello".into())), "\"hello\"");
    }

    #[test]
    fn encode_string_escapes() {
        let s = Value::String("a\"b\\c\nd".into());
        assert_eq!(encode(&s), "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn encode_string_control_chars() {
        let s = Value::String("\x01\x1f".into());
        assert_eq!(encode(&s), "\"\\u0001\\u001f\"");
    }

    #[test]
    fn encode_empty_array() {
        assert_eq!(encode(&Value::Array(vec![])), "[]");
    }

    #[test]
    fn encode_array() {
        let arr = Value::Array(vec![Value::Number(1.0), Value::Bool(true), Value::Null]);
        assert_eq!(encode(&arr), "[1,true,null]");
    }

    #[test]
    fn encode_empty_object() {
        assert_eq!(encode(&Value::Object(BTreeMap::new())), "{}");
    }

    #[test]
    fn encode_object() {
        let mut obj = BTreeMap::new();
        obj.insert("a".into(), Value::Number(1.0));
        obj.insert("b".into(), Value::String("two".into()));
        let s = encode(&Value::Object(obj));
        assert_eq!(s, "{\"a\":1,\"b\":\"two\"}");
    }

    // ---- Decode tests ---------------------------------------------------

    #[test]
    fn decode_null() {
        assert_eq!(decode("null").unwrap(), Value::Null);
    }

    #[test]
    fn decode_true() {
        assert_eq!(decode("true").unwrap(), Value::Bool(true));
    }

    #[test]
    fn decode_false() {
        assert_eq!(decode("false").unwrap(), Value::Bool(false));
    }

    #[test]
    fn decode_integer() {
        assert_eq!(decode("42").unwrap(), Value::Number(42.0));
    }

    #[test]
    fn decode_negative() {
        assert_eq!(decode("-7").unwrap(), Value::Number(-7.0));
    }

    #[test]
    fn decode_float() {
        assert_eq!(decode("3.25").unwrap(), Value::Number(3.25));
    }

    #[test]
    fn decode_exponent() {
        assert_eq!(decode("1e3").unwrap(), Value::Number(1000.0));
        assert_eq!(decode("2.5E-1").unwrap(), Value::Number(0.25));
    }

    #[test]
    fn decode_string() {
        assert_eq!(decode("\"hello\"").unwrap(), Value::String("hello".into()));
    }

    #[test]
    fn decode_string_escapes() {
        let v = decode("\"a\\\"b\\\\c\\n\\t\"").unwrap();
        assert_eq!(v.as_str().unwrap(), "a\"b\\c\n\t");
    }

    #[test]
    fn decode_string_unicode_escape() {
        let v = decode("\"\\u0041\"").unwrap();
        assert_eq!(v.as_str().unwrap(), "A");
    }

    #[test]
    fn decode_string_surrogate_pair() {
        // U+1F600 = 😀 = \uD83D\uDE00
        let v = decode("\"\\uD83D\\uDE00\"").unwrap();
        assert_eq!(v.as_str().unwrap(), "😀");
    }

    #[test]
    fn decode_empty_array() {
        assert_eq!(decode("[]").unwrap(), Value::Array(vec![]));
    }

    #[test]
    fn decode_array() {
        let v = decode("[1, true, null, \"x\"]").unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0], Value::Number(1.0));
        assert_eq!(arr[1], Value::Bool(true));
        assert_eq!(arr[2], Value::Null);
        assert_eq!(arr[3], Value::String("x".into()));
    }

    #[test]
    fn decode_empty_object() {
        assert_eq!(decode("{}").unwrap(), Value::Object(BTreeMap::new()));
    }

    #[test]
    fn decode_object() {
        let v = decode("{\"a\": 1, \"b\": \"two\"}").unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("a").unwrap(), &Value::Number(1.0));
        assert_eq!(obj.get("b").unwrap(), &Value::String("two".into()));
    }

    #[test]
    fn decode_nested() {
        let v = decode("{\"arr\": [1, {\"deep\": true}]}").unwrap();
        let arr = v.get("arr").unwrap().as_array().unwrap();
        assert_eq!(arr[1].get("deep").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn decode_whitespace_tolerance() {
        let v = decode("  { \"a\" :  1 }  ").unwrap();
        assert_eq!(v.get("a").unwrap().as_f64(), Some(1.0));
    }

    // ---- Error tests ----------------------------------------------------

    #[test]
    fn reject_trailing_content() {
        let err = decode("true false").unwrap_err();
        assert!(matches!(err, JsonError::TrailingContent(_)));
    }

    #[test]
    fn reject_unterminated_string() {
        let err = decode("\"hello").unwrap_err();
        assert!(matches!(err, JsonError::UnterminatedString));
    }

    #[test]
    fn reject_invalid_escape() {
        let err = decode("\"\\x\"").unwrap_err();
        assert!(matches!(err, JsonError::InvalidEscape(_)));
    }

    #[test]
    fn reject_depth_exceeded() {
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        let err = decode(&deep).unwrap_err();
        assert!(matches!(err, JsonError::DepthExceeded));
    }

    #[test]
    fn reject_empty_input() {
        let err = decode("").unwrap_err();
        assert!(matches!(err, JsonError::UnexpectedEof));
    }

    #[test]
    fn reject_invalid_number_leading_zero() {
        // "01" is not valid JSON (no leading zeros except bare "0").
        // Our parser accepts "0" then sees trailing "1".
        let err = decode("01").unwrap_err();
        assert!(matches!(err, JsonError::TrailingContent(_)));
    }

    // ---- Round-trip tests -----------------------------------------------

    #[test]
    fn roundtrip_simple_values() {
        for input in &["null", "true", "false", "42", "-7", "\"hello\"", "[]", "{}"] {
            let v = decode(input).unwrap();
            let encoded = encode(&v);
            let v2 = decode(&encoded).unwrap();
            assert_eq!(v, v2, "roundtrip failed for {input}");
        }
    }

    #[test]
    fn roundtrip_complex() {
        let input = r#"{"arr":[1,2,3],"nested":{"a":true,"b":null},"s":"hello\nworld"}"#;
        let v = decode(input).unwrap();
        let encoded = encode(&v);
        let v2 = decode(&encoded).unwrap();
        assert_eq!(v, v2);
    }

    // ---- Accessor tests -------------------------------------------------

    #[test]
    fn value_accessors() {
        assert!(Value::Null.is_null());
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
        assert_eq!(Value::Number(3.25).as_f64(), Some(3.25));
        assert_eq!(Value::String("x".into()).as_str(), Some("x"));
        assert!(Value::Array(vec![]).as_array().is_some());
        assert!(Value::Object(BTreeMap::new()).as_object().is_some());
    }

    #[test]
    fn value_wrong_type_returns_none() {
        assert_eq!(Value::Null.as_bool(), None);
        assert_eq!(Value::Null.as_f64(), None);
        assert_eq!(Value::Null.as_str(), None);
        assert_eq!(Value::Null.as_array(), None);
        assert_eq!(Value::Null.as_object(), None);
        assert_eq!(Value::Null.get("x"), None);
    }

    // ---- Error display --------------------------------------------------

    #[test]
    fn error_display() {
        assert_eq!(JsonError::UnexpectedEof.to_string(), "unexpected end of input");
        assert_eq!(JsonError::DepthExceeded.to_string(), "nesting depth exceeded (max 32)");
    }
}
