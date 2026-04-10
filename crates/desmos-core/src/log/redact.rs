//! Field-level redactor. Replaces values of secret-looking field names
//! with `***` before they reach a sink or the ring buffer.
//!
//! Matching is case-insensitive so `Password`, `PASSWORD`, and `password`
//! are all redacted.

use std::borrow::Cow;

const SECRET_KEYS: &[&str] = &["psk", "password", "private_key"];

pub fn redact<'a>(key: &str, value: &'a str) -> Cow<'a, str> {
    if SECRET_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key)) {
        Cow::Borrowed("***")
    } else {
        Cow::Borrowed(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_psk() {
        assert_eq!(redact("psk", "abc123").as_ref(), "***");
    }

    #[test]
    fn redacts_password() {
        assert_eq!(redact("password", "hunter2").as_ref(), "***");
    }

    #[test]
    fn redacts_private_key() {
        assert_eq!(redact("private_key", "MIIEvQIBADAN...").as_ref(), "***");
    }

    #[test]
    fn passes_through_non_secret_fields() {
        assert_eq!(redact("iface", "eth0").as_ref(), "eth0");
        assert_eq!(redact("count", "42").as_ref(), "42");
    }

    #[test]
    fn match_is_case_insensitive() {
        assert_eq!(redact("PSK", "x").as_ref(), "***");
        assert_eq!(redact("Password", "x").as_ref(), "***");
        assert_eq!(redact("PRIVATE_KEY", "x").as_ref(), "***");
    }
}
