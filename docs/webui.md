# Web UI Reference

The Desmos Web UI is a React single-page application embedded in the
binary at compile time. It is served by the hand-rolled HTTP server on
`127.0.0.1:8080` by default.

## Authentication

All API endpoints (except `/api/v1/health` and `/api/v1/version`) require
HTTP Basic Auth. Credentials are configured in the `[webui]` section of
the configuration file. Passwords are hashed with PBKDF2-HMAC-SHA256.

## Pages

### Dashboard (`#dashboard`)

Live overview of tunnel health.

- **Tunnel status badge**: up (green), connecting (blue), degraded (amber),
  down (red), unknown (grey)
- **Throughput chart**: Rolling 60-second line chart of TX/RX bytes per
  second, updated via WebSocket at 2 Hz
- **Total transfer**: Cumulative TX and RX bytes
- **Interface bandwidth bars**: Per-interface TX/RX progress bars with
  RTT, loss, and jitter metrics
- **Session info**: Current strategy, uptime, session ID

### Interfaces (`#interfaces`)

Table of all configured network interfaces.

| Column   | Description                            |
|----------|----------------------------------------|
| Name     | Interface name (eth0, wlan0, etc.)     |
| State    | Link health: healthy, probation, degraded, dead |
| RTT      | Round-trip time in milliseconds        |
| Loss     | Packet loss percentage                 |
| Jitter   | Jitter in milliseconds                 |
| TX       | Total bytes transmitted                |
| RX       | Total bytes received                   |
| Weight   | Configured weight (0-1000)             |
| Enabled  | ON/OFF toggle button                   |

Toggling the enable button sends `PUT /api/v1/interfaces/:name` with
`{ "enabled": true/false }`.

### Bonding (`#bonding`)

Bonding engine configuration.

- **Strategy dropdown**: Hot-switch between Round-Robin, Weighted,
  Latency-Adaptive, and Redundant strategies via
  `PUT /api/v1/bonding/strategy`
- **Link stats**: Active, degraded, and dead link counts
- **Weight sliders**: Per-interface weight sliders (0-1000), visible only
  when the Weighted strategy is selected. Debounced at 300 ms to avoid
  flooding the API

### Connections (`#connections`)

Server mode only. Lists connected clients.

| Column    | Description                          |
|-----------|--------------------------------------|
| Session   | Session ID                           |
| Identity  | Authentication identity              |
| Connected | Connection timestamp                 |
| TX        | Bytes transmitted to client          |
| RX        | Bytes received from client           |
| Action    | Kick button                          |

The Kick button sends `DELETE /api/v1/clients/:session_id`.

### Logs (`#logs`)

Live log stream via WebSocket.

- **Level filter**: Dropdown to select minimum log level
  (trace, debug, info, warn, error)
- **Log viewer**: Scrollable monospace area with color-coded level badges
- **Auto-scroll**: Automatically scrolls to the latest entry unless the
  user has scrolled up
- **Buffer**: Retains up to 500 entries client-side

### Settings (`#settings`)

TOML configuration editor.

- **Editor**: Monospace textarea with the current configuration
- **Validation**: Client-side TOML syntax validation (bracket balance,
  key=value structure). Save button is disabled when syntax errors exist
- **Save**: Submits `PUT /api/v1/config` with the raw TOML body
- **Hot-reload safety**: The server rejects changes to fields that require
  a restart (mode, listen address, identity keys) with HTTP 409 Conflict

## REST API Endpoints

### Public (no authentication)

| Method | Path              | Description        |
|--------|-------------------|--------------------|
| GET    | /api/v1/health    | Health check       |
| GET    | /api/v1/version   | Version info       |

### Authenticated (Basic Auth)

| Method | Path                       | Description                         |
|--------|----------------------------|-------------------------------------|
| GET    | /api/v1/status             | Tunnel and link status              |
| GET    | /api/v1/interfaces         | List interfaces                     |
| GET    | /api/v1/bonding            | Bonding engine state                |
| GET    | /api/v1/stats              | Traffic statistics (JSON/Prometheus) |
| GET    | /api/v1/clients            | Connected clients (server mode)     |
| GET    | /api/v1/config             | Current config (secrets redacted)   |
| GET    | /api/v1/logs               | Recent log entries                  |
| PUT    | /api/v1/interfaces/:name   | Update interface settings           |
| PUT    | /api/v1/bonding/strategy   | Set bonding strategy                |
| PUT    | /api/v1/config             | Hot-reload configuration (TOML)     |
| DELETE | /api/v1/clients/:session_id| Kick a client                       |

### WebSocket

| Path                | Description                        |
|---------------------|------------------------------------|
| /api/v1/ws/stats    | Live stats stream (2 Hz)           |
| /api/v1/ws/logs     | Live log stream (?level= filter)   |

### Query Parameters

**GET /api/v1/stats**:
- `format=prometheus` — Return Prometheus text exposition format
- Default: JSON envelope

**GET /api/v1/logs**:
- `limit=N` — Max entries (default 100, max 1000)
- `level=<level>` — Minimum level filter (debug/info/warn/error)

**GET /api/v1/ws/logs**:
- `level=<level>` — Minimum level filter (trace/debug/info/warn/error)

## Response Envelope

All JSON responses use a standard envelope:

**Success:**
```json
{
  "data": { ... },
  "meta": {
    "request_id": "0x1a2b",
    "generated_at_us": 1744291200000000
  }
}
```

**Error:**
```json
{
  "error": {
    "code": "invalid_json",
    "message": "Expected a JSON object",
    "details": { ... }
  },
  "meta": {
    "request_id": "0x1a2c"
  }
}
```

## Embedded SPA

The frontend is compiled by Vite at build time and embedded via
`include_bytes!` in `build.rs`. Static assets under `/assets/` are served
with `Cache-Control: public, max-age=31536000, immutable` (hashed
filenames). The root `/` serves `index.html`.

To build without the frontend (no Node.js required):

```bash
cargo build -p desmos-webui --no-default-features
```
