# Getting Started

This guide walks through installing Desmos, generating keys, configuring a
client-server pair, starting the tunnel, and verifying that bonded traffic
flows correctly.

## Prerequisites

| Requirement        | Minimum                                              |
|--------------------|------------------------------------------------------|
| Operating system   | Linux (kernel 3.17+), macOS 11+, Windows 10+, FreeBSD 13+ |
| Rust toolchain     | 1.75.0 (only for building from source)               |
| Privileges         | Root / Administrator (TUN device creation)            |
| Network interfaces | At least 2 for bonding (1 works but provides no aggregation) |
| UDP port           | 4900 (default, configurable)                         |

## 1. Install

### Option A: Download a release binary

Visit the [Releases](https://github.com/KilimcininKorOglu/desmos/releases)
page and download the archive for your platform.

**Linux x86_64:**

```bash
curl -LO https://github.com/KilimcininKorOglu/desmos/releases/latest/download/desmos-x86_64-unknown-linux-musl.tar.gz
tar xzf desmos-x86_64-unknown-linux-musl.tar.gz
sudo install -m 755 desmos /usr/local/bin/desmos
```

**Linux aarch64:**

```bash
curl -LO https://github.com/KilimcininKorOglu/desmos/releases/latest/download/desmos-aarch64-unknown-linux-musl.tar.gz
tar xzf desmos-aarch64-unknown-linux-musl.tar.gz
sudo install -m 755 desmos /usr/local/bin/desmos
```

**macOS (Apple Silicon):**

```bash
curl -LO https://github.com/KilimcininKorOglu/desmos/releases/latest/download/desmos-aarch64-apple-darwin.tar.gz
tar xzf desmos-aarch64-apple-darwin.tar.gz
sudo install -m 755 desmos /usr/local/bin/desmos
```

**Windows:**

Download `desmos-1.1.0-x64.msi` from the releases page and run the installer.
The MSI places `desmos.exe` into `C:\Program Files\Desmos\` and adds it to
`PATH`. You also need `wintun.dll` from [wintun.net](https://www.wintun.net/)
in the same directory as `desmos.exe`.

**FreeBSD:**

```bash
curl -LO https://github.com/KilimcininKorOglu/desmos/releases/latest/download/desmos-x86_64-unknown-freebsd.tar.gz
tar xzf desmos-x86_64-unknown-freebsd.tar.gz
sudo install -m 755 desmos /usr/local/bin/desmos
```

### Option B: Build from source

```bash
git clone https://github.com/KilimcininKorOglu/desmos.git
cd desmos
cargo build --release
sudo install -m 755 target/release/desmos /usr/local/bin/desmos
```

For a fully static Linux binary:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Option C: OpenWrt

See `packaging/openwrt/` for the IPK Makefile and init scripts. Cross-compile
with `--no-default-features` to skip the Web UI (OpenWrt devices have no
Node.js):

```bash
cross build --release --target armv7-unknown-linux-musleabihf --no-default-features
```

### Verify installation

```bash
desmos version
# Expected output: desmos 1.1.0
```

## 2. Generate keys

Desmos uses X25519 static key pairs for the Noise IK handshake. Each side
(client and server) needs its own key pair.

Generate a 32-byte random private key:

```bash
# Linux / macOS
head -c 32 /dev/urandom > server.key
chmod 600 server.key

head -c 32 /dev/urandom > client.key
chmod 600 client.key
```

```powershell
# Windows (PowerShell)
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[System.IO.File]::WriteAllBytes("server.key", $bytes)

$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[System.IO.File]::WriteAllBytes("client.key", $bytes)
```

Extract the hex-encoded public key from a private key file:

```bash
# The public key is derived from the private key during the handshake.
# For configuration, encode the 32-byte private key as 64-char hex:
xxd -p -c 64 server.key
xxd -p -c 64 client.key
```

The server config needs the server's own public key. The client config needs
the server's public key. Exchange the server's hex-encoded key to the client
through a secure channel.

## 3. Configure the server

Create the configuration directory and file:

```bash
sudo mkdir -p /etc/desmos
sudo cp config/desmos.toml.example /etc/desmos/server.toml
sudo cp server.key /etc/desmos/server.key
sudo chmod 600 /etc/desmos/server.key
```

Edit `/etc/desmos/server.toml`:

```toml
[general]
mode = "server"
log_level = "info"
tunnel_mtu = 1400

[server]
listen = "0.0.0.0:4900"
public_key = "<server-hex-public-key>"
private_key_file = "/etc/desmos/server.key"
max_clients = 100

[server.auth]
method = "psk"
psk = "my-secret-pre-shared-key"

[webui]
enabled = true
listen = "127.0.0.1:8080"
username = "admin"
password_hash = "$pbkdf2-sha256$i=600000$<base64-salt>$<base64-hash>"
```

Validate the config:

```bash
desmos config validate --config /etc/desmos/server.toml
# Expected output: configuration is valid
```

### Firewall

Open UDP port 4900 (or your configured port):

```bash
# Linux (iptables)
sudo iptables -A INPUT -p udp --dport 4900 -j ACCEPT

# Linux (nftables)
sudo nft add rule inet filter input udp dport 4900 accept

# FreeBSD (pf)
echo "pass in proto udp to port 4900" | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf

# Windows
netsh advfirewall firewall add rule name="Desmos VPN" dir=in action=allow protocol=UDP localport=4900
```

## 4. Configure the client

```bash
sudo mkdir -p /etc/desmos
sudo cp client.key /etc/desmos/client.key
sudo chmod 600 /etc/desmos/client.key
```

Create `/etc/desmos/client.toml`:

```toml
[general]
mode = "client"
log_level = "info"
tunnel_mtu = 1400

[client]
server = "your-server-ip:4900"
server_public_key = "<server-hex-public-key>"
private_key_file = "/etc/desmos/client.key"
bonding_strategy = "latency-adaptive"
reorder_window_ms = 50
dns_leak_protection = true
dns_servers = ["1.1.1.1", "8.8.8.8"]

[[client.interfaces]]
name = "eth0"
weight = 100
enabled = true

[[client.interfaces]]
name = "wlan0"
weight = 80
enabled = true
```

Identify your interface names with:

```bash
desmos interfaces
```

Use the names from the `NAME` column in `[[client.interfaces]]` entries.

Validate:

```bash
desmos config validate --config /etc/desmos/client.toml
```

## 5. Start the server

```bash
sudo desmos up --config /etc/desmos/server.toml
```

On Linux with systemd, the packaged unit file handles this:

```bash
sudo systemctl enable --now desmos
```

The server logs to stderr by default. Check the log output for:

```
level=info target=daemon msg=started
level=info target=server msg=listening addr=0.0.0.0:4900
level=info target=server msg=reactor loop started
```

## 6. Start the client

```bash
sudo desmos up --config /etc/desmos/client.toml
```

Expected log output:

```
level=info target=daemon msg=started
level=info target=daemon msg=tun created iface=desmos0
level=info target=daemon msg=socket bound link_id=1 iface=eth0 local=0.0.0.0:51234
level=info target=daemon msg=socket bound link_id=2 iface=wlan0 local=0.0.0.0:51235
level=info target=daemon msg=handshake complete
level=info target=daemon msg=reactor loop started links=2
```

## 7. Verify the tunnel

### Check status

```bash
desmos status
```

Expected output:

```json
{"data":{"tunnel_state":"up","uptime_s":42,"strategy":"latency-adaptive","link_count":2,"interfaces":[...]}}
```

### Test connectivity

From the client, ping through the tunnel:

```bash
ping -c 5 10.0.0.1
```

### Test bonding

Measure throughput with both interfaces active, then disable one to verify
failover:

```bash
# Full bonded throughput
iperf3 -c <server-tunnel-ip> -t 10

# Disable one interface to test failover
sudo ip link set wlan0 down
iperf3 -c <server-tunnel-ip> -t 10

# Re-enable
sudo ip link set wlan0 up
```

### Check the Web UI

If `[webui]` is enabled, open `http://127.0.0.1:8080` in a browser. The
dashboard shows live throughput charts, interface status, and connected
clients.

## 8. Monitor and manage

### CLI commands

```bash
desmos status          # Tunnel state, uptime, strategy
desmos interfaces      # List all host network interfaces
desmos stats           # Aggregate byte/packet counters
desmos bonding         # Current strategy and link health
desmos clients         # Connected sessions (server mode)
desmos logs            # Recent log entries
```

Add `--json` to any command for machine-readable output.

### Switch bonding strategy at runtime

The Web UI bonding page has a dropdown, or use the REST API:

```bash
curl -u admin:<password> -X PUT http://127.0.0.1:8080/api/v1/bonding \
  -H "Content-Type: application/json" \
  -d '{"strategy":"round-robin"}'
```

Available strategies: `round-robin`, `weighted`, `latency-adaptive`, `redundant`.

### Update interface weights at runtime

```bash
curl -u admin:<password> -X PUT http://127.0.0.1:8080/api/v1/interfaces/eth0 \
  -H "Content-Type: application/json" \
  -d '{"weight":200}'
```

### Kick a client (server mode)

```bash
desmos clients kick <session-id>
```

### Reload configuration

```bash
desmos reload
```

### Stop the tunnel

```bash
desmos down
```

Or send `SIGTERM` / `SIGINT` (Ctrl+C) to the running process.

## 9. Bonding strategies explained

| Strategy          | Behavior                                                    | Best for                           |
|-------------------|-------------------------------------------------------------|------------------------------------|
| `round-robin`     | Packets distributed equally across all healthy links        | Equal-speed links                  |
| `weighted`        | Packets distributed proportionally to configured weight     | Asymmetric links (e.g. 100M + 50M)|
| `latency-adaptive`| Favors the link with the lowest measured RTT                | Mixed link quality (default)       |
| `redundant`       | Every packet sent on all links simultaneously               | Maximum reliability, low bandwidth |

Strategies are hot-swappable at runtime. The bonding engine atomically replaces
the active strategy without dropping a single packet.

## 10. Configuration reference

### [general]

| Field        | Type   | Default | Range       | Description                    |
|--------------|--------|---------|-------------|--------------------------------|
| `mode`       | string | -       | client/server/p2p | Operating mode (required) |
| `log_level`  | string | info    | trace/debug/info/warn/error | Log verbosity |
| `tunnel_mtu` | u16    | 1400    | 576-9000    | Tunnel MTU in bytes            |

### [server]

| Field              | Type   | Default | Description                          |
|--------------------|--------|---------|--------------------------------------|
| `listen`           | string | -       | UDP bind address (e.g. `0.0.0.0:4900`) |
| `public_key`       | string | -       | Server X25519 public key (hex)       |
| `private_key_file` | string | -       | Path to 32-byte private key file     |
| `max_clients`      | u32    | 100     | Maximum concurrent sessions          |

### [server.auth]

| Field                 | Type   | Description                              |
|-----------------------|--------|------------------------------------------|
| `method`              | string | `psk`, `pubkey`, `totp`, or `mtls`       |
| `psk`                 | string | Pre-shared key (for `psk` method)        |
| `authorized_keys_file`| string | One public key per line (for `pubkey`)   |
| `totp_secret`         | string | Base32-encoded TOTP secret               |
| `ca_cert_file`        | string | CA certificate path (for `mtls`)         |

### [client]

| Field                | Type   | Default            | Description                        |
|----------------------|--------|--------------------|------------------------------------|
| `server`             | string | -                  | Server endpoint (`host:port`)      |
| `server_public_key`  | string | -                  | Server X25519 public key (hex)     |
| `private_key_file`   | string | -                  | Path to client private key         |
| `bonding_strategy`   | string | latency-adaptive   | Bonding strategy name              |
| `reorder_window_ms`  | u32    | 50                 | Reorder buffer window (0-10000 ms) |
| `dns_leak_protection`| bool   | false              | Override system DNS resolvers      |
| `dns_servers`        | array  | []                 | DNS servers for the tunnel         |

### [[client.interfaces]]

| Field     | Type   | Default | Range    | Description                       |
|-----------|--------|---------|----------|-----------------------------------|
| `name`    | string | -       | -        | Kernel interface name              |
| `weight`  | u32    | 10      | 0-1000   | Weight for bonding distribution    |
| `enabled` | bool   | true    | -        | Include in bonding                 |

### [webui]

| Field           | Type   | Default        | Description                     |
|-----------------|--------|----------------|---------------------------------|
| `enabled`       | bool   | false          | Enable the Web UI               |
| `listen`        | string | 127.0.0.1:8080 | HTTP bind address               |
| `username`      | string | -              | Basic Auth username             |
| `password_hash` | string | -              | PBKDF2-HMAC-SHA256 PHC string  |

### [p2p]

| Field            | Type   | Description                             |
|------------------|--------|-----------------------------------------|
| `peer_public_key`| string | Peer X25519 public key (hex)            |
| `peer_endpoint`  | string | Peer endpoint for initial contact       |
| `stun_servers`   | array  | STUN servers for NAT traversal          |
| `relay_servers`  | array  | Relay servers for fallback connectivity |

## 11. Platform-specific notes

### Linux

- TUN device creation requires `CAP_NET_ADMIN` (or root).
- Per-interface socket binding uses `SO_BINDTODEVICE` (requires `CAP_NET_RAW`
  on interfaces other than `lo`).
- After TUN + socket creation, Desmos drops to uid/gid 65534 (nobody).
- systemd unit file at `packaging/linux/systemd/desmos.service`.

### macOS

- Uses `utun` kernel interface. Requires root.
- Per-interface binding via `IP_BOUND_IF` setsockopt.
- No privilege drop yet (planned).

### Windows

- Requires `wintun.dll` (download from [wintun.net](https://www.wintun.net/)).
- Runs as a Windows Service (`sc start Desmos`) or interactively.
- Per-interface binding via `IP_UNICAST_IF` setsockopt.
- MSI installer registers the service automatically.

### FreeBSD

- Uses `tun` device. Requires root.
- Per-interface binding not yet available; sockets bind `0.0.0.0:0`.

### OpenWrt

- IPK package installs to `/usr/bin/desmos` with a procd init script.
- UCI configuration at `/etc/config/desmos` (bridge to TOML by init script).
- LuCI web interface at Network > VPN > Desmos.
- MIPS (ath79) is not supported on stable Rust 1.75. ARM (ipq40xx) and
  aarch64 (mediatek-filogic) are supported.

## 12. Troubleshooting

| Symptom                           | Cause                                      | Fix                                      |
|-----------------------------------|--------------------------------------------|------------------------------------------|
| `daemon not running`              | Desmos is not started                      | `sudo desmos up --config <path>`         |
| `No such file or directory`       | TUN device creation failed                 | Run with `sudo` / check `CAP_NET_ADMIN`  |
| `WSAECONNRESET` on Windows        | Missing `SIO_UDP_CONNRESET` disable        | Update to latest binary (auto-handled)   |
| `Permission denied` on bind       | Interface binding needs `CAP_NET_RAW`      | Run as root or grant capability           |
| Handshake timeout                 | Server unreachable or wrong public key     | Check firewall, verify key hex string     |
| Low throughput with bonding       | Reorder window too small                   | Increase `reorder_window_ms` (try 100)   |
| Single link used despite 2 ifaces | Second interface disabled or dead           | Check `desmos interfaces`, verify `enabled = true` |
| Web UI not loading                | `[webui] enabled = false` or wrong bind    | Set `enabled = true`, check `listen` addr |
| `configuration is valid` but crash| Key file missing or wrong permissions      | Check file exists, `chmod 600`            |
