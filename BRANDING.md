# Desmos — Branding Guide

> Identity, visual language, and voice for the Desmos project. Scope matches the product: a developer-first, self-hosted system tool. Medium depth — name, logo, color, typography, voice, CLI aesthetic, Web UI tokens, README conventions.

---

## 1. Name & Identity

### 1.1 Project Name

- **Name:** Desmos
- **Pronunciation:** `dez-mos` (IPA: /ˈdɛz.mɒs/). Stress on the first syllable. Rhymes with "cosmos".
- **Etymology:** From the Ancient Greek δεσμός — "bond, link, tie, fastening". The word names what the product does: it ties independent network links together into one. It is also the origin of related English words like "desmotropism" and "desmosome" (the cell junctions that bind tissues).
- **In code / filenames / packages:** lowercase, `desmos`. Package names: `desmos`, `desmos-core`, `desmos-proto`. Never `Desmos-CLI`, never `DESMOS`.
- **In prose:** Capitalized, `Desmos`. Not all-caps. Not possessive without an apostrophe (`Desmos's config`, not `Desmos config`). The product is referred to in the singular (`Desmos is a bonding VPN`, not `Desmos are`).
- **Conflict note:** There is an unrelated mathematics graphing calculator called Desmos. We will not use it in any marketing copy that could be confused with that product. Project tagline always includes "bonding VPN" or "connection bonding" to disambiguate in search.

### 1.2 Tagline

- **Primary:** *"Bond every link."*
- **Technical:** *"Connection bonding VPN for Linux, macOS, Windows, FreeBSD, OpenWrt, and pfSense."*
- **Marketing:** *"Combine every network you have into one faster, more reliable tunnel."*

### 1.3 Elevator Pitch

Desmos is an open-source connection bonding VPN written in Rust. It combines Wi-Fi, Ethernet, LTE, and any other network interface into a single encrypted tunnel that is both faster and more reliable than any link alone. A single static binary ships on six platforms with only five external dependencies — auditable, self-hosted, and fully under your control.

---

## 2. Logo

### 2.1 Concept

Two curved lines that cross and converge into a single point, forming a stylized **knot** or **bond**. The crossing lines represent independent network links; the convergence point represents the bonded tunnel. The shape should read as abstract and geometric, not literal rope or cable.

Visual principles:

- **Geometric, not organic.** Bezier curves with rational control points. No hand-drawn lines.
- **Works monochrome.** Has to look right in a terminal in a single color, in a white GitHub header, and on a dark background.
- **One concept, one shape.** No embellishment, no shadow, no gradient in the primary mark.
- **Recognizable at 16 px.** The favicon test.

### 2.2 Specifications

| Variant       | Description                                                              | Minimum Size | Clear Space |
|---------------|--------------------------------------------------------------------------|--------------|-------------|
| Primary mark  | Full logo: knot glyph + "desmos" wordmark on the right                   | 128 px wide  | 1× glyph height |
| Icon mark     | Knot glyph alone, square-bound                                           | 16 px        | 0.25× glyph height |
| Wordmark      | "desmos" text-only, geometric sans                                       | 48 px wide   | 0.5× cap height |
| Inverted      | Any of the above in a single light tint on a dark background             | same         | same        |

### 2.3 AI Generation Prompt

Use this prompt with an image generator for first-draft explorations. Treat outputs as directional, not final.

```
A minimal geometric logo mark for an open-source networking tool called "Desmos".
Two curved lines crossing and converging into a single focal point, forming an
abstract stylized knot or bond. Flat 2D, pure vector style, single color
(#14B8A6 teal) on a transparent background. Square 1:1 composition, centered,
thick uniform stroke weight, no gradient, no shadow, no 3D effects, no text,
no photorealistic elements. The final shape must remain legible at 16x16 pixels.
Inspired by Greek meander patterns and minimalist mathematical symbols.
```

Avoid: literal cables, knotted rope, handshake imagery, globes, locks, network topology diagrams with nodes and edges, any text inside the mark.

---

## 3. Color Palette

Dark mode is the **default**. Light mode is available but secondary. All colors satisfy WCAG AA 4.5:1 contrast for body text.

### 3.1 Brand Colors

| Role       | Name         | Hex       | RGB                 | Usage                                                   |
|------------|--------------|-----------|---------------------|---------------------------------------------------------|
| Primary    | Bond Teal    | `#14B8A6` | rgb(20, 184, 166)   | Logo, primary buttons, links, active nav, brand accents |
| Secondary  | Cable Cyan   | `#06B6D4` | rgb(6, 182, 212)    | Graph lines, hover states, secondary accents            |
| Accent     | Signal Amber | `#F59E0B` | rgb(245, 158, 11)   | Warnings, probation-state badges, highlights            |

### 3.2 Neutrals

| Role              | Hex (Dark)    | Hex (Light)   | Usage                                           |
|-------------------|---------------|---------------|-------------------------------------------------|
| Background        | `#0B1220`     | `#F8FAFC`     | Page background                                 |
| Surface           | `#111B2E`     | `#FFFFFF`     | Cards, panels, tables                           |
| Surface Elevated  | `#18243B`     | `#F1F5F9`     | Hover, modals, dropdowns                        |
| Border            | `#1F2A44`     | `#E2E8F0`     | Dividers, input borders                         |
| Text Primary      | `#E2E8F0`     | `#0F172A`     | Headings, body text                             |
| Text Secondary    | `#94A3B8`     | `#475569`     | Captions, disabled, placeholders                |
| Text Muted        | `#64748B`     | `#64748B`     | Labels, hints, metadata                         |

### 3.3 Semantic Colors

| Role    | Hex       | Usage                                                  |
|---------|-----------|--------------------------------------------------------|
| Success | `#22C55E` | Healthy link state, tunnel `up`, confirmations         |
| Error   | `#EF4444` | Dead link state, tunnel `down`, destructive actions    |
| Warning | `#F59E0B` | Degraded link, auth failure, probation                 |
| Info    | `#3B82F6` | Informational notices, neutral highlights              |

### 3.4 Link-State Color Mapping

Specific mapping for Web UI and CLI status output:

| State     | Color           | Hex       | ANSI (CLI)             |
|-----------|-----------------|-----------|------------------------|
| Healthy   | Success green   | `#22C55E` | `\x1b[32m` (green)     |
| Probation | Warning amber   | `#F59E0B` | `\x1b[33m` (yellow)    |
| Degraded  | Signal amber    | `#F59E0B` | `\x1b[33m` (yellow)    |
| Dead      | Error red       | `#EF4444` | `\x1b[31m` (red)       |
| Unknown   | Text secondary  | `#94A3B8` | `\x1b[90m` (bright black) |

### 3.5 CSS Variables

```css
:root {
  --color-primary:        #14B8A6;
  --color-secondary:      #06B6D4;
  --color-accent:         #F59E0B;
  --color-bg:             #0B1220;
  --color-surface:        #111B2E;
  --color-surface-elev:   #18243B;
  --color-border:         #1F2A44;
  --color-text:           #E2E8F0;
  --color-text-secondary: #94A3B8;
  --color-text-muted:     #64748B;
  --color-success:        #22C55E;
  --color-error:          #EF4444;
  --color-warning:        #F59E0B;
  --color-info:           #3B82F6;
}

:root[data-theme="light"] {
  --color-bg:             #F8FAFC;
  --color-surface:        #FFFFFF;
  --color-surface-elev:   #F1F5F9;
  --color-border:         #E2E8F0;
  --color-text:           #0F172A;
  --color-text-secondary: #475569;
}
```

---

## 4. Typography

### 4.1 Font Stack

| Role     | Font           | Weights      | Fallback                                        | License       |
|----------|----------------|--------------|-------------------------------------------------|---------------|
| Headings | Inter          | 600, 700     | `-apple-system, BlinkMacSystemFont, sans-serif` | OFL           |
| Body     | Inter          | 400, 500     | `-apple-system, BlinkMacSystemFont, sans-serif` | OFL           |
| Code     | JetBrains Mono | 400, 500     | `ui-monospace, "SF Mono", Menlo, monospace`     | OFL           |

Both fonts are free, open-source, and bundled with the Web UI as self-hosted WOFF2 files so no CDN connection leaks from the admin dashboard.

### 4.2 Type Scale

| Element    | Size       | Weight | Line Height | Use                                 |
|------------|------------|--------|-------------|-------------------------------------|
| H1         | 2.25rem    | 700    | 1.2         | Page titles                         |
| H2         | 1.75rem    | 600    | 1.3         | Section headers                     |
| H3         | 1.375rem   | 600    | 1.4         | Card titles, sub-sections           |
| H4         | 1.125rem   | 600    | 1.4         | Table group headers                 |
| Body       | 1rem       | 400    | 1.6         | Paragraphs                          |
| Small      | 0.875rem   | 400    | 1.5         | Captions, helper text               |
| Tiny       | 0.75rem    | 500    | 1.4         | Labels, badges                      |
| Code       | 0.9rem     | 400    | 1.5         | Inline and block code               |

Tabular numerals (`font-variant-numeric: tabular-nums`) on all metrics tables and throughput displays.

---

## 5. Voice & Tone

### 5.1 Personality

Desmos speaks like a **senior network engineer writing an internal design doc**. Four adjectives:

- **Precise.** Every sentence names a concrete thing. No weasel words.
- **Terse.** If a word adds nothing, it isn't there. No "actually", "simply", "just".
- **Technical.** Assumes the reader knows what a TUN device is. Does not apologize for that.
- **Trustworthy.** Says what it does and does not do. No hype. No superlatives without numbers.

### 5.2 Writing Rules

- **Headlines** state behavior, not benefit. `Bond every link.` ✓ — `The fastest VPN you'll ever use.` ✗
- **Documentation** is factual and verifiable. Every claim has a number, a code example, or a link to the RFC.
- **Error messages** name the failing thing, the reason, and the fix. `TUN create failed: CAP_NET_ADMIN missing. Run with sudo or grant the capability.` ✓
- **CLI output** is scannable. Table columns over sentences. JSON behind `--json`.
- **READMEs and blog posts** avoid emoji. The project is professional, not playful.
- **No exclamation marks** except in direct quotes or code comments where they are syntactic.
- **Numbers and units** are always precise. `< 1 ms` not "fast". `≥ 2 Gbps` not "high throughput". `5 crates` not "minimal dependencies".

### 5.3 Vocabulary

| Prefer                        | Avoid                                      |
|-------------------------------|--------------------------------------------|
| Bond                          | Merge, aggregate, combine (for links)      |
| Link                          | Connection (ambiguous, use only for TCP)   |
| Interface                     | NIC, adapter                               |
| Tunnel                        | Pipe, channel (ambiguous)                  |
| Handshake                     | Connection setup, negotiation              |
| Session                       | Connection, socket, peer                   |
| Operator                      | User, admin, customer                      |
| Self-host                     | Install on your own hardware               |
| Drop                          | Silently reject (for packets)              |
| Audit                         | Review, check                              |
| Hand-rolled                   | Custom, from scratch                       |
| Free and open source          | Free, OSS, gratis                          |

### 5.4 Error Message Rubric

Every error message follows: **`<component>: <what failed>. <why>. <how to fix>.`**

Examples:

```
ok:
  config: invalid bonding_strategy "burst". Must be one of:
          round-robin, weighted, latency-adaptive, redundant.
  tun: create desmos0 failed. Missing CAP_NET_ADMIN. Run with sudo or
       grant the capability via setcap.
  handshake: PSK mismatch. Server rejected the shared key. Verify
             [server.auth].psk on both peers.

not ok:
  "Something went wrong"
  "Error: 0x800"
  "Please try again"
```

---

## 6. Visual Language

### 6.1 Border Radius

Uniform `--radius: 6px` on buttons, cards, inputs. `--radius-sm: 3px` on badges and tags. `--radius-lg: 12px` on modals and toasts. No full-round pills — they feel consumer, not technical.

### 6.2 Shadows

Dark mode uses **no shadows**. Elevation is conveyed by surface color (`--color-surface` → `--color-surface-elev`). Light mode has one shadow:

```css
--shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.05);
--shadow-md: 0 2px 8px rgba(15, 23, 42, 0.08);
```

### 6.3 Spacing Scale

Base unit: **4 px**. Scale: 4, 8, 12, 16, 24, 32, 48, 64. Use the scale token names rather than raw pixels.

```css
--space-1: 4px;
--space-2: 8px;
--space-3: 12px;
--space-4: 16px;
--space-6: 24px;
--space-8: 32px;
--space-12: 48px;
--space-16: 64px;
```

### 6.4 Icons

**Lucide** icon set. Outline style, 1.5 px stroke, 16 px and 20 px sizes. Imported per-icon (tree-shaken) so the embedded bundle stays small. No FontAwesome, no Material Icons — too bulky and carry brand baggage.

Icon-to-concept mapping:

| Concept           | Icon              |
|-------------------|-------------------|
| Tunnel up         | `activity`        |
| Tunnel down       | `power-off`       |
| Interface         | `cable`           |
| Healthy link      | `check-circle`    |
| Dead link         | `x-circle`        |
| Degraded link     | `alert-triangle`  |
| Bonding strategy  | `git-merge`       |
| Settings          | `settings`        |
| Logs              | `terminal`        |
| Keys              | `key-round`       |
| Clients           | `users`           |
| Dashboard         | `layout-dashboard`|

---

## 7. CLI Aesthetic

The CLI is as much a brand surface as the Web UI. Rules:

- **Colored output by default**, disabled by `--no-color` or when `NO_COLOR` env var is set (honor the `no-color.org` standard).
- **One color per meaning**: green = healthy/ok, yellow = warning/probation, red = error/dead, teal = brand accent, gray = metadata.
- **Tables use box-drawing characters** (`─ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼`) on terminals that support UTF-8, ASCII (`- | + + + + + +`) otherwise.
- **Progress and status are one-liners**, not spinners, so they work over SSH and in logs.
- **`--json` disables all decoration** and emits one compact JSON object per line.

Example `desmos status` output:

```
desmos 1.0.0  tunnel: up  session: 0x11  uptime: 11h 45m  strategy: latency-adaptive

Interfaces (3)
  name    state      rtt      loss     jitter    weight   rx       tx
  eth0    healthy    4.2 ms   0.0%     0.3 ms    100      41 GB    19 GB
  wlan0   probation  28.1 ms  1.4%     4.1 ms    60       12 GB     8 GB
  wwan0   degraded   310 ms   18.0%    45 ms     20       2.1 GB  830 MB

Throughput (last 60s)
  rx: 142 Mbps   tx: 38 Mbps   reorder p99: 0.8 ms
```

---

## 8. Web UI Aesthetic

- **Dark mode is the default.** A light mode toggle is available in Settings; the system never auto-switches based on OS preference without explicit user opt-in.
- **Layout** is a fixed left sidebar with navigation, a top bar with tunnel status and user menu, and a main content region. Sidebar collapses below 1024 px.
- **Data density** is high. Tables are dense by default; a density toggle is not provided in v1.0.
- **Charts** use `--color-primary` and `--color-secondary` as the two series colors. No multi-hue rainbow scales. Gridlines use `--color-border`.
- **Empty states** show a short technical line ("No interfaces configured. Edit `[client.interfaces]` in desmos.toml."), not illustrated mascots.
- **Animations** are minimal: 150 ms for hover, 200 ms for modal enter/exit, no page transitions.

---

## 9. README Conventions

The project README is the most-read artifact. Rules:

- **Emoji-free.** Section headers use plain Markdown.
- **Hero block**: logo (SVG or PNG), tagline, one-paragraph elevator pitch, two badges (build status, license).
- **Structure** (in order): Overview, Features, Install (with per-platform tabs as subsections), Quick Start, Configuration, Documentation links, Contributing, License.
- **Code blocks** use language hints (```` ```rust ````, ```` ```bash ````).
- **Screenshots** (if any) are stored under `docs/assets/` and referenced with relative paths — never embedded data URIs.
- **No marketing bullets** ("🚀 Blazing fast", "✨ Beautiful UI"). Replace with numbers: "≥ 2 Gbps single-core throughput" or a link to the benchmark report.
- **License line** is a plain sentence: `Desmos is released under the MIT License. See LICENSE.`

### 9.1 README Skeleton

```markdown
# Desmos

**Bond every link.**

Desmos is an open-source connection bonding VPN written in Rust. It combines
Wi-Fi, Ethernet, LTE, and any other network interface into a single encrypted
tunnel that is both faster and more reliable than any link alone.

[![CI](https://img.shields.io/github/actions/workflow/status/<org>/desmos/ci.yml?branch=main)](...)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- Bond 2-8 interfaces into a single encrypted tunnel
- Four scheduling strategies: Round-Robin, Weighted, Latency-Adaptive, Redundant
- Sub-second failover on interface loss
- Client-server and P2P modes
- Runs on Linux, macOS, Windows, FreeBSD, OpenWrt, pfSense
- Single static binary, five external dependencies

## Install

<per-platform instructions>

## Quick Start

<minimal working config + run command>

## Documentation

- `docs/architecture.md` — how Desmos is structured
- `docs/protocol.md`     — DWP wire format
- `docs/cli.md`          — CLI reference
- `docs/webui.md`        — Web UI reference

## Contributing

See `CONTRIBUTING.md`.

## License

Desmos is released under the MIT License. See `LICENSE`.
```

---

## 10. Assets Checklist

| Asset               | Format       | Size              | Path                              | Status |
|---------------------|--------------|-------------------|-----------------------------------|--------|
| Logo (full)         | SVG + PNG    | vector / 1024 px  | `docs/assets/logo.{svg,png}`      | TBD    |
| Icon (mark only)    | SVG + PNG    | 512, 192, 64 px   | `docs/assets/icon-{size}.png`     | TBD    |
| Favicon             | ICO + PNG    | 32, 16 px         | `crates/desmos-webui/web/public/` | TBD    |
| OG Image            | PNG          | 1200 × 630        | `docs/assets/og-image.png`        | TBD    |
| Social Banner       | PNG          | 1500 × 500        | `docs/assets/banner.png`          | TBD    |
| README Header       | SVG          | 800 × 200         | `docs/assets/readme-header.svg`   | TBD    |
| Web UI Logo         | SVG          | vector            | `crates/desmos-webui/web/src/assets/logo.svg` | TBD |
| CLI ASCII Art       | text         | 60 cols wide      | `crates/desmos-cli/src/art.txt`   | TBD    |

---

## Quality Checklist

- [x] Name is memorable and searchable (with "bonding VPN" qualifier to disambiguate from the math product).
- [x] Tagline is under 10 words.
- [x] Color palette meets WCAG AA contrast on dark and light modes.
- [x] Fonts are free/open source (Inter + JetBrains Mono, OFL).
- [x] CSS variables provided for every token.
- [x] Link-state color mapping covers all four states (+ unknown).
- [x] CLI ANSI mapping documented for no-color-capable terminals.
- [x] README skeleton matches the voice rules.
- [x] Assets checklist lists every launch deliverable.
