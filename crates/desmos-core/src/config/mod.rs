//! Hand-rolled TOML subset parser and typed `Value` tree.
//!
//! The supported subset is intentionally narrow and sized for the Desmos
//! configuration schema. It accepts:
//!
//! - Tables via `[section]` and `[a.b.c]` dotted headers
//! - Arrays of tables via `[[section]]` and `[[a.b]]`
//! - Basic double-quoted strings with `\\`, `\"`, `\n`, `\t`, `\r`, `\\` escapes
//! - Signed integers
//! - Signed floats with a fractional part (no scientific notation)
//! - Booleans `true` / `false`
//! - Arrays of primitives
//! - `#`-prefixed line comments
//!
//! It deliberately does **not** accept: inline tables `{ a = 1 }`, dotted
//! keys on the left of `=`, multi-line strings, scientific notation, or
//! heterogeneous arrays.

pub mod diff;
pub mod lexer;
pub mod schema;
pub mod validate;

pub use validate::AuthConfig;
pub use validate::AuthMethod;
pub use validate::BondingStrategy;
pub use validate::ClientConfig;
pub use validate::Config;
pub use validate::GeneralConfig;
pub use validate::InterfaceConfig;
pub use validate::LogLevel;
pub use validate::Mode;
pub use validate::P2pConfig;
pub use validate::ServerConfig;
pub use validate::WebuiConfig;

use core::fmt;
use std::collections::BTreeMap;

/// A parsed TOML value tree. Root is always a `Table`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<Value>),
    Table(BTreeMap<String, Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::String(_) => "string",
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::Boolean(_) => "boolean",
            Self::Array(_) => "array",
            Self::Table(_) => "table",
        }
    }

    pub fn as_table(&self) -> Option<&BTreeMap<String, Value>> {
        if let Self::Table(t) = self {
            Some(t)
        } else {
            None
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        if let Self::Integer(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        if let Self::Float(f) = self {
            Some(*f)
        } else {
            None
        }
    }

    pub fn as_boolean(&self) -> Option<bool> {
        if let Self::Boolean(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        if let Self::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }
}

/// A path through a parsed `Value` tree, rendered as `a.b.c` in errors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Path(Vec<String>);

impl Path {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, segment: impl Into<String>) {
        self.0.push(segment.into());
    }

    pub fn joined(segments: &[&str]) -> Self {
        Self(segments.iter().map(|s| (*s).to_string()).collect())
    }

    pub fn render(&self) -> String {
        if self.0.is_empty() {
            "<root>".to_string()
        } else {
            self.0.join(".")
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// A parsing or lookup error against a TOML document.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub line: usize,
    pub col: usize,
    pub path: Path,
}

impl ParseError {
    pub fn new(kind: ParseErrorKind, line: usize, col: usize) -> Self {
        Self { kind, line, col, path: Path::new() }
    }

    pub fn with_path(mut self, path: Path) -> Self {
        self.path = path;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParseErrorKind {
    UnexpectedChar(char),
    UnterminatedString,
    InvalidEscape(char),
    InvalidNumber(String),
    UnexpectedToken { expected: &'static str, got: String },
    DuplicateKey(String),
    UnknownSection(String),
    TypeMismatch { expected: &'static str, got: &'static str },
    MissingField(String),
    OutOfRange(String),
    Eof,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: ", self.line, self.col)?;
        match &self.kind {
            ParseErrorKind::UnexpectedChar(c) => write!(f, "unexpected_char: {c:?}"),
            ParseErrorKind::UnterminatedString => write!(f, "unterminated_string"),
            ParseErrorKind::InvalidEscape(c) => write!(f, "invalid_escape: \\{c}"),
            ParseErrorKind::InvalidNumber(s) => write!(f, "invalid_number: {s}"),
            ParseErrorKind::UnexpectedToken { expected, got } => {
                write!(f, "unexpected_token: expected {expected}, got {got}")
            }
            ParseErrorKind::DuplicateKey(k) => write!(f, "duplicate_key: {k}"),
            ParseErrorKind::UnknownSection(name) => write!(f, "unknown_section: {name}"),
            ParseErrorKind::TypeMismatch { expected, got } => {
                write!(f, "type_mismatch: {}: expected {expected}, got {got}", self.path)
            }
            ParseErrorKind::MissingField(name) => {
                write!(f, "missing_field: {}.{}", self.path, name)
            }
            ParseErrorKind::OutOfRange(name) => {
                write!(f, "out_of_range: {}.{}", self.path, name)
            }
            ParseErrorKind::Eof => write!(f, "unexpected_eof"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a TOML document into a `Value::Table`.
pub fn parse(input: &str) -> Result<Value, ParseError> {
    let tokens = lexer::tokenize(input)?;
    schema::Parser::new(tokens).parse_document()
}

/// Render a `Value` tree back to TOML text. Used by property tests to verify
/// a round-trip and by redacted config snapshots.
pub fn to_toml(value: &Value) -> String {
    let mut out = String::new();
    write_toml_table(&mut out, value.as_table().expect("to_toml root must be a Table"), &[]);
    out
}

fn write_toml_value(out: &mut String, v: &Value) {
    match v {
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Integer(i) => out.push_str(&i.to_string()),
        Value::Float(f) => {
            let s = format!("{f:?}");
            out.push_str(&s);
        }
        Value::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_toml_value(out, item);
            }
            out.push(']');
        }
        Value::Table(_) => {}
    }
}

fn write_toml_table(out: &mut String, table: &BTreeMap<String, Value>, path: &[String]) {
    // First pass: scalar and array-of-primitive leaves under this header.
    let has_leaves = table.values().any(|v| {
        !matches!(v, Value::Table(_) | Value::Array(_))
            || matches!(v, Value::Array(arr) if arr.iter().all(|v| !matches!(v, Value::Table(_))))
    });
    if has_leaves {
        if !path.is_empty() {
            out.push('[');
            out.push_str(&path.join("."));
            out.push_str("]\n");
        }
        for (k, v) in table {
            match v {
                Value::Table(_) => {}
                Value::Array(arr) if arr.iter().any(|v| matches!(v, Value::Table(_))) => {}
                _ => {
                    out.push_str(k);
                    out.push_str(" = ");
                    write_toml_value(out, v);
                    out.push('\n');
                }
            }
        }
        out.push('\n');
    }

    for (k, v) in table {
        match v {
            Value::Table(nested) => {
                let mut sub = path.to_vec();
                sub.push(k.clone());
                write_toml_table(out, nested, &sub);
            }
            Value::Array(arr)
                if arr.iter().all(|v| matches!(v, Value::Table(_))) && !arr.is_empty() =>
            {
                let mut sub = path.to_vec();
                sub.push(k.clone());
                for item in arr {
                    if let Value::Table(t) = item {
                        out.push_str("[[");
                        out.push_str(&sub.join("."));
                        out.push_str("]]\n");
                        let mut inner_tables: Vec<(&String, &Value)> = Vec::new();
                        for (ik, iv) in t {
                            if matches!(iv, Value::Table(_)) {
                                inner_tables.push((ik, iv));
                            } else {
                                out.push_str(ik);
                                out.push_str(" = ");
                                write_toml_value(out, iv);
                                out.push('\n');
                            }
                        }
                        out.push('\n');
                        for (ik, iv) in inner_tables {
                            if let Value::Table(nested) = iv {
                                let mut sub2 = sub.clone();
                                sub2.push(ik.clone());
                                write_toml_table(out, nested, &sub2);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_document() {
        let v = parse("").unwrap();
        assert_eq!(v, Value::Table(BTreeMap::new()));
    }

    #[test]
    fn parses_single_section_with_primitives() {
        let src = r#"
[general]
mode = "client"
log_level = "info"
tunnel_mtu = 1400
"#;
        let v = parse(src).unwrap();
        let t = v.as_table().unwrap();
        let g = t.get("general").unwrap().as_table().unwrap();
        assert_eq!(g.get("mode").unwrap().as_string(), Some("client"));
        assert_eq!(g.get("log_level").unwrap().as_string(), Some("info"));
        assert_eq!(g.get("tunnel_mtu").unwrap().as_integer(), Some(1400));
    }

    #[test]
    fn parses_dotted_section_headers() {
        let src = r#"
[server.auth]
method = "psk"
psk = "secret"
"#;
        let v = parse(src).unwrap();
        let server = v.as_table().unwrap().get("server").unwrap().as_table().unwrap();
        let auth = server.get("auth").unwrap().as_table().unwrap();
        assert_eq!(auth.get("method").unwrap().as_string(), Some("psk"));
    }

    #[test]
    fn parses_array_of_tables() {
        let src = r#"
[[client.interfaces]]
name = "eth0"
weight = 100
enabled = true

[[client.interfaces]]
name = "wlan0"
weight = 80
enabled = true
"#;
        let v = parse(src).unwrap();
        let client = v.as_table().unwrap().get("client").unwrap().as_table().unwrap();
        let ifaces = client.get("interfaces").unwrap().as_array().unwrap();
        assert_eq!(ifaces.len(), 2);
        let first = ifaces[0].as_table().unwrap();
        assert_eq!(first.get("name").unwrap().as_string(), Some("eth0"));
        assert_eq!(first.get("weight").unwrap().as_integer(), Some(100));
        assert_eq!(first.get("enabled").unwrap().as_boolean(), Some(true));
    }

    #[test]
    fn parses_primitive_arrays() {
        let src = r#"dns = ["1.1.1.1", "8.8.8.8"]
ports = [80, 443, 8080]
weights = [1.5, 2.0, 0.25]
flags = [true, false]
"#;
        let v = parse(src).unwrap();
        let t = v.as_table().unwrap();
        let dns = t.get("dns").unwrap().as_array().unwrap();
        assert_eq!(dns.len(), 2);
        assert_eq!(dns[0].as_string(), Some("1.1.1.1"));
        assert_eq!(t.get("ports").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(t.get("weights").unwrap().as_array().unwrap()[1].as_float(), Some(2.0));
        assert_eq!(t.get("flags").unwrap().as_array().unwrap()[1].as_boolean(), Some(false));
    }

    #[test]
    fn comments_are_skipped() {
        let src = "# leading comment\n[a] # trailing\nk = 1 # end of line\n";
        let v = parse(src).unwrap();
        let a = v.as_table().unwrap().get("a").unwrap().as_table().unwrap();
        assert_eq!(a.get("k").unwrap().as_integer(), Some(1));
    }

    #[test]
    fn string_escapes_decoded() {
        let src = r#"msg = "hello\n\tworld\"quoted\"""#;
        let v = parse(src).unwrap();
        assert_eq!(
            v.as_table().unwrap().get("msg").unwrap().as_string(),
            Some("hello\n\tworld\"quoted\"")
        );
    }

    #[test]
    fn negative_integers_and_floats() {
        let src = "a = -42\nb = -2.5\n";
        let v = parse(src).unwrap();
        let t = v.as_table().unwrap();
        assert_eq!(t.get("a").unwrap().as_integer(), Some(-42));
        assert_eq!(t.get("b").unwrap().as_float(), Some(-2.5));
    }

    #[test]
    fn duplicate_key_errors() {
        let src = "a = 1\na = 2\n";
        let e = parse(src).unwrap_err();
        assert!(matches!(e.kind, ParseErrorKind::DuplicateKey(_)));
    }

    #[test]
    fn unterminated_string_errors() {
        let src = "a = \"oops\n";
        let e = parse(src).unwrap_err();
        assert!(matches!(e.kind, ParseErrorKind::UnterminatedString));
    }

    #[test]
    fn error_display_includes_path_for_type_mismatch() {
        let e = ParseError::new(
            ParseErrorKind::TypeMismatch { expected: "integer", got: "string" },
            0,
            0,
        )
        .with_path(Path::joined(&["server", "listen_port"]));
        let rendered = e.to_string();
        assert!(
            rendered.contains("type_mismatch: server.listen_port: expected integer, got string")
        );
    }

    #[test]
    fn error_display_unknown_section() {
        let e = ParseError::new(ParseErrorKind::UnknownSection("madeup".into()), 0, 0);
        assert!(e.to_string().contains("unknown_section: madeup"));
    }

    #[test]
    fn to_toml_roundtrip_simple() {
        let src = "[a]\nk = 1\ns = \"x\"\n\n";
        let v = parse(src).unwrap();
        let rendered = to_toml(&v);
        let v2 = parse(&rendered).unwrap();
        assert_eq!(v, v2);
    }
}
