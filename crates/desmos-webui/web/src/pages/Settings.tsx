/**
 * Settings page.
 *
 * TOML configuration editor with client-side validation.
 * Loads current config from `GET /api/v1/config`, displays in
 * a monospace editor, and submits via `PUT /api/v1/config`.
 */

import { useFetch } from "../hooks/useFetch";
import { TomlEditor } from "../components/TomlEditor";
import type { ApiResponse } from "../api";

interface ConfigData {
  [key: string]: unknown;
}

/**
 * Convert a flat JSON config object to a minimal TOML representation.
 * This is a best-effort formatter for the stub config data.
 */
function jsonToTomlStub(data: Record<string, unknown>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === "string") {
      lines.push(`${key} = "${value}"`);
    } else if (typeof value === "number" || typeof value === "boolean") {
      lines.push(`${key} = ${String(value)}`);
    } else if (Array.isArray(value)) {
      const items = value.map((v) =>
        typeof v === "string" ? `"${v}"` : String(v),
      );
      lines.push(`${key} = [${items.join(", ")}]`);
    }
  }
  return lines.join("\n") + "\n";
}

/** Placeholder TOML shown when config data is empty or loading. */
const PLACEHOLDER_TOML = `# Desmos Configuration
# Edit below and click Save to apply.

[general]
mode = "client"
log_level = "info"
tunnel_mtu = 1400

[client]
server = "vpn.example.com:4789"
bonding_strategy = "latency-adaptive"
reorder_window_ms = 50
dns_leak_protection = true
`;

export function Settings() {
  const { data: resp, loading } = useFetch<ApiResponse<ConfigData>>("/api/v1/config");

  const configData = resp?.data;
  const initialToml = configData && Object.keys(configData).length > 0
    ? jsonToTomlStub(configData as Record<string, unknown>)
    : PLACEHOLDER_TOML;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
      <div>
        <h2 style={{ fontSize: "1.25rem", fontWeight: 700, marginBottom: "var(--space-1)" }}>
          Settings
        </h2>
        <p
          style={{
            fontSize: "0.8125rem",
            color: "var(--color-text-secondary)",
          }}
        >
          Edit the TOML configuration below. Changes that require a restart
          will be rejected — only hot-reloadable fields are accepted.
        </p>
      </div>

      {loading && (
        <p style={{ color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
          Loading configuration...
        </p>
      )}

      {!loading && <TomlEditor initialValue={initialToml} />}
    </div>
  );
}
