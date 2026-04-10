# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Cargo workspace scaffolding (7 crates, pinned toolchain, lint configs, deny policy).
- `desmos-core` error taxonomy (`CoreError`, `ConfigError`, `IoError`) and `Result` alias.
- `desmos-core` structured logger: `log!` macro, `Level`, `Entry`, stderr sink, 500-entry bounded ring, secret-field redactor (`psk`, `password`, `private_key`).
