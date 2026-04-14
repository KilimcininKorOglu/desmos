/**
 * Connections page (server mode).
 *
 * Lists connected clients from `GET /api/v1/clients` with a kick
 * button per row that calls `DELETE /api/v1/clients/:session_id`.
 */

import { useCallback, useState } from "react";
import { useFetch } from "../hooks/useFetch";
import { apiDelete } from "../api";
import type { ApiResponse } from "../api";

interface ClientEntry {
  session_id: number;
  identity: string;
  connected_at_us: number;
  tx_bytes: number;
  rx_bytes: number;
}

interface ClientsData {
  clients: ClientEntry[];
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatTimestamp(us: number): string {
  if (us === 0) return "-";
  const d = new Date(us / 1000);
  return d.toLocaleString();
}

export function Connections() {
  const { data: resp, loading } = useFetch<ApiResponse<ClientsData>>("/api/v1/clients");
  const [kickedIds, setKickedIds] = useState<Set<number>>(new Set());
  const [kickError, setKickError] = useState<string | null>(null);

  const clients = resp?.data.clients ?? [];

  const handleKick = useCallback(async (sessionId: number) => {
    setKickError(null);
    try {
      await apiDelete(`/api/v1/clients/${sessionId}`);
      setKickedIds((prev) => new Set(prev).add(sessionId));
    } catch (err) {
      setKickError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  const activeClients = clients.filter((c) => !kickedIds.has(c.session_id));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1.25rem", fontWeight: 700 }}>Connections</h2>

      {loading && (
        <p style={{ color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
          Loading...
        </p>
      )}

      {kickError && (
        <p style={{ color: "var(--color-error)", fontSize: "0.8125rem" }}>
          Kick failed: {kickError}
        </p>
      )}

      {activeClients.length === 0 && !loading && (
        <p style={{ color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
          No connected clients.
        </p>
      )}

      {activeClients.length > 0 && (
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
              <tr style={{ borderBottom: "1px solid var(--color-border)", textAlign: "left" }}>
                {["Session", "Identity", "Connected", "TX", "RX", ""].map((h) => (
                  <th
                    key={h || "action"}
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
                ))}
              </tr>
            </thead>
            <tbody>
              {activeClients.map((client) => (
                <ClientRow
                  key={client.session_id}
                  client={client}
                  onKick={handleKick}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ClientRow({
  client,
  onKick,
}: {
  client: ClientEntry;
  onKick: (id: number) => void;
}) {
  const [busy, setBusy] = useState(false);

  async function handleClick() {
    setBusy(true);
    onKick(client.session_id);
  }

  const cellStyle: React.CSSProperties = {
    padding: "var(--space-2) var(--space-3)",
    whiteSpace: "nowrap",
    borderBottom: "1px solid var(--color-border)",
  };

  return (
    <tr>
      <td style={{ ...cellStyle, fontWeight: 600 }}>{client.session_id}</td>
      <td style={cellStyle}>{client.identity || "-"}</td>
      <td style={cellStyle}>{formatTimestamp(client.connected_at_us)}</td>
      <td style={cellStyle}>{formatBytes(client.tx_bytes)}</td>
      <td style={cellStyle}>{formatBytes(client.rx_bytes)}</td>
      <td style={cellStyle}>
        <button
          onClick={handleClick}
          disabled={busy}
          style={{
            padding: "var(--space-1) var(--space-2)",
            borderRadius: "var(--radius-sm)",
            border: "1px solid var(--color-error)",
            background: "transparent",
            color: "var(--color-error)",
            cursor: busy ? "wait" : "pointer",
            fontSize: "0.6875rem",
            fontWeight: 600,
          }}
        >
          Kick
        </button>
      </td>
    </tr>
  );
}
