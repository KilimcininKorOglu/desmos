/**
 * Interface table with enable/disable toggle and weight editing.
 *
 * Each row shows: name, state, RTT, loss, jitter, weight, enabled toggle.
 * Toggling or changing weight sends `PUT /api/v1/interfaces/:name`.
 */

import { useState } from "react";
import { apiPut } from "../api";

export interface InterfaceRow {
  name: string;
  state: string;
  rtt_us: number;
  loss_pct: number;
  jitter_us: number;
  tx_bytes: number;
  rx_bytes: number;
  weight: number;
  enabled: boolean;
}

interface InterfaceTableProps {
  interfaces: InterfaceRow[];
  onUpdated?: () => void;
}

const stateColors: Record<string, string> = {
  healthy: "var(--color-link-healthy)",
  probation: "var(--color-link-probation)",
  degraded: "var(--color-link-degraded)",
  dead: "var(--color-link-dead)",
  unknown: "var(--color-link-unknown)",
};

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function InterfaceTable({ interfaces, onUpdated }: InterfaceTableProps) {
  if (interfaces.length === 0) {
    return (
      <p style={{ color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
        No interfaces configured.
      </p>
    );
  }

  return (
    <div
      style={{
        overflowX: "auto",
        border: "1px solid var(--color-border)",
        borderRadius: "var(--radius)",
        background: "var(--color-surface)",
      }}
    >
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: "0.8125rem",
          fontFamily: "var(--font-code)",
        }}
      >
        <thead>
          <tr
            style={{
              borderBottom: "1px solid var(--color-border)",
              textAlign: "left",
            }}
          >
            {["Name", "State", "RTT", "Loss", "Jitter", "TX", "RX", "Weight", "Enabled"].map(
              (h) => (
                <th
                  key={h}
                  style={{
                    padding: "var(--space-2) var(--space-3)",
                    color: "var(--color-text-secondary)",
                    fontWeight: 600,
                    fontSize: "0.6875rem",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                    whiteSpace: "nowrap",
                  }}
                >
                  {h}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {interfaces.map((iface) => (
            <InterfaceRow key={iface.name} iface={iface} onUpdated={onUpdated} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function InterfaceRow({
  iface,
  onUpdated,
}: {
  iface: InterfaceRow;
  onUpdated?: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const stateColor = stateColors[iface.state] ?? stateColors["unknown"];

  async function toggleEnabled() {
    setBusy(true);
    setError(null);
    try {
      await apiPut(`/api/v1/interfaces/${encodeURIComponent(iface.name)}`, {
        enabled: !iface.enabled,
      });
      onUpdated?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const cellStyle: React.CSSProperties = {
    padding: "var(--space-2) var(--space-3)",
    whiteSpace: "nowrap",
    borderBottom: "1px solid var(--color-border)",
  };

  return (
    <tr style={{ opacity: iface.enabled ? 1 : 0.5 }}>
      <td style={{ ...cellStyle, fontWeight: 600 }}>{iface.name}</td>
      <td style={cellStyle}>
        <span style={{ color: stateColor }}>{iface.state}</span>
      </td>
      <td style={cellStyle}>{(iface.rtt_us / 1000).toFixed(1)} ms</td>
      <td style={cellStyle}>{iface.loss_pct.toFixed(1)}%</td>
      <td style={cellStyle}>{(iface.jitter_us / 1000).toFixed(1)} ms</td>
      <td style={cellStyle}>{formatBytes(iface.tx_bytes)}</td>
      <td style={cellStyle}>{formatBytes(iface.rx_bytes)}</td>
      <td style={cellStyle}>{iface.weight}</td>
      <td style={cellStyle}>
        <button
          onClick={toggleEnabled}
          disabled={busy}
          style={{
            padding: "var(--space-1) var(--space-2)",
            borderRadius: "var(--radius-sm)",
            border: "1px solid var(--color-border)",
            background: iface.enabled ? "var(--color-success)" : "var(--color-surface-elev)",
            color: iface.enabled ? "#fff" : "var(--color-text-muted)",
            cursor: busy ? "wait" : "pointer",
            fontSize: "0.6875rem",
            fontWeight: 600,
            minWidth: 42,
          }}
        >
          {iface.enabled ? "ON" : "OFF"}
        </button>
        {error && (
          <span style={{ color: "var(--color-error)", fontSize: "0.6875rem", marginLeft: "var(--space-2)" }}>
            {error}
          </span>
        )}
      </td>
    </tr>
  );
}
