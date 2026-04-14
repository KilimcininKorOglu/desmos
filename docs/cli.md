# CLI Reference

The `desmos` binary provides 12 subcommands for managing the VPN tunnel,
bonding engine, and connected clients.

## Global Options

```
desmos [subcommand] [options]

Options:
  --config <path>    Configuration file path (default: /etc/desmos/config.toml)
  --json             Output in JSON format (disables color/decoration)
  --no-color         Disable colored output (also respects NO_COLOR env var)
  --version          Print version and exit
  --help             Print help and exit
```

## Subcommands

### up

Bring the tunnel up. Reads the configuration file, binds sockets to each
configured interface, creates the TUN device, performs the handshake, and
starts the bonding engine.

```bash
# Start with default config
desmos up

# Start with a custom config file
desmos up --config /path/to/config.toml

# Start in foreground (no daemonize)
desmos up --foreground
```

### down

Tear the tunnel down gracefully. Sends FIN to the peer, closes sockets,
removes the TUN device, and restores DNS if leak protection was active.

```bash
desmos down
```

### status

Show current tunnel and link status. Displays tunnel state, session ID,
uptime, active strategy, and per-interface link health.

```bash
# Human-readable output
desmos status

# JSON output for scripting
desmos status --json
```

### reload

Hot-reload the running configuration. Only reload-safe fields are applied;
unsafe changes (mode, listen address, keys) are rejected with an error.

```bash
desmos reload

# Reload a specific config file
desmos reload --config /path/to/new-config.toml
```

### config

Validate, show, or generate configuration.

```bash
# Validate the config file
desmos config validate

# Show the active config (secrets redacted)
desmos config show

# Generate a default config to stdout
desmos config generate
```

### bonding

Show or hot-switch the bonding strategy.

```bash
# Show current strategy and link counts
desmos bonding

# Switch to a different strategy
desmos bonding --strategy latency-adaptive
desmos bonding --strategy round-robin
desmos bonding --strategy weighted
desmos bonding --strategy redundant
```

### interfaces

List, enable, disable, or reweight bonded interfaces.

```bash
# List all interfaces with link quality metrics
desmos interfaces

# Enable an interface
desmos interfaces enable eth0

# Disable an interface
desmos interfaces disable wlan0

# Set weight (0-1000)
desmos interfaces weight eth0 200
```

### clients

List or kick connected clients (server mode only).

```bash
# List all connected clients
desmos clients

# Kick a client by session ID
desmos clients kick 42
```

### stats

Print aggregate traffic statistics.

```bash
# Human-readable output
desmos stats

# Prometheus text format
desmos stats --format prometheus

# JSON output
desmos stats --json
```

### logs

Tail recent log entries.

```bash
# Show last 100 log entries (default)
desmos logs

# Show last N entries
desmos logs --limit 50

# Filter by minimum level
desmos logs --level warn

# Follow new entries (live tail)
desmos logs --follow
```

### webui

Manage the embedded Web UI.

```bash
# Set the Web UI password (interactive prompt)
desmos webui set-password

# Show the current bind address
desmos webui status

# Change the bind address
desmos webui bind 127.0.0.1:8080
```

### version

Print version information and exit.

```bash
desmos version
```

Output:

```
desmos 0.1.0
```

## Exit Codes

| Code | Meaning                         |
|------|---------------------------------|
| 0    | Success                         |
| 1    | General error                   |
| 2    | Configuration error             |
| 3    | Permission denied               |
| 4    | Network error                   |
| 5    | Peer unreachable                |

## Environment Variables

| Variable    | Description                              |
|-------------|------------------------------------------|
| `NO_COLOR`  | Disable colored output when set          |
| `DESMOS_LOG`| Override log level (trace/debug/info/warn/error) |
