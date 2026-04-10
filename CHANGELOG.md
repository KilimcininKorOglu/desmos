# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Cargo workspace scaffolding (7 crates, pinned toolchain, lint configs, deny policy).
- `desmos-core` error taxonomy (`CoreError`, `ConfigError`, `IoError`) and `Result` alias.
- `desmos-core` structured logger: `log!` macro, `Level`, `Entry`, stderr sink, 500-entry bounded ring, secret-field redactor (`psk`, `password`, `private_key`).
- `desmos-core::config` hand-rolled TOML subset parser (lexer + recursive-descent parser), `Value` tree, `Path` / `ParseError` / `ParseErrorKind` with `path.to.field` Display, `to_toml` serializer, 29 unit tests plus a deterministic 1000-case round-trip fuzzer using a seeded xorshift64 RNG.
- `desmos-core::config::validate` strongly typed `Config` tree (`GeneralConfig`, `ServerConfig`, `ClientConfig`, `WebuiConfig`, `P2pConfig`, `AuthConfig`, `InterfaceConfig`) plus `Mode`, `LogLevel`, `AuthMethod`, `BondingStrategy` enums; `Config::from_value` with `missing_field` / `out_of_range` / `type_mismatch` / `unknown_section` error reporting; Argon2id PHC syntactic recognizer.
- `config/desmos.toml.example` fully commented reference configuration covering client, server, p2p, and Web UI sections.
