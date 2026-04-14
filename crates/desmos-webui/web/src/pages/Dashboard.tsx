/**
 * Dashboard page.
 *
 * Displays:
 * - Tunnel status badge (up/connecting/degraded/down)
 * - Real-time throughput chart via `/api/v1/ws/stats`
 * - Per-interface bandwidth bars
 * - Session info (strategy, uptime, session ID)
 */

import { useEffect, useRef, useMemo } from "react";
import { useFetch } from "../hooks/useFetch";
import { useWsStream } from "../hooks/useWsStream";
import { TunnelStatusBadge } from "../components/TunnelStatusBadge";
import {
  ThroughputChart,
  type ThroughputSample,
} from "../components/ThroughputChart";
import type { ApiResponse } from "../api";

// ---------- API response types ----------

interface StatusInterface {
  name: string;
  state: string;
  rtt_us: number;
}

interface StatusData {
  tunnel_state: string;
  session_id: number;
  uptime_s: number;
  strategy: string;
  interfaces: StatusInterface[];
}

interface StatsInterface {
  name: string;
  tx_bytes: number;
  rx_bytes: number;
  tx_packets: number;
  rx_packets: number;
  rtt_us: number;
  loss_pct: number;
  jitter_us: number;
}

interface StatsData {
  total_tx_bytes: number;
  total_rx_bytes: number;
  interfaces: StatsInterface[];
}

// ---------- Helpers ----------

/** Format seconds into a human-readable uptime string. */
function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

/** Format bytes as a human-readable string. */
function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

// ---------- Component ----------

export function Dashboard() {
  const { data: statusResp } = useFetch<ApiResponse<StatusData>>("/api/v1/status");
  const { latest: wsStats, connected: wsConnected } = useWsStream<ApiResponse<StatsData>>("/api/v1/ws/stats");

  // Track previous total bytes to compute per-second rates.
  const prevTotals = useRef<{ tx: number; rx: number } | null>(null);

  // Compute throughput sample from delta between WS frames.
  const throughputSample = useMemo<ThroughputSample | null>(() => {
    if (!wsStats) return null;
    const stats = wsStats.data;
    const prev = prevTotals.current;
    prevTotals.current = { tx: stats.total_tx_bytes, rx: stats.total_rx_bytes };

    if (!prev) return null;

    // WS pushes at ~2 Hz, so delta is ~0.5s. Normalize to per-second.
    const txDelta = Math.max(0, stats.total_tx_bytes - prev.tx);
    const rxDelta = Math.max(0, stats.total_rx_bytes - prev.rx);

    return { txBps: txDelta * 2, rxBps: rxDelta * 2 };
  }, [wsStats]);

  // Update previous totals ref when wsStats changes (already done in useMemo).
  // We use a separate effect to reset when WS reconnects.
  useEffect(() => {
    if (!wsConnected) {
      prevTotals.current = null;
    }
  }, [wsConnected]);

  const status = statusResp?.data;
  const stats = wsStats?.data;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
      {/* Header row */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "var(--space-4)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-4)" }}>
          <h2 style={{ fontSize: "1.25rem", fontWeight: 700 }}>Dashboard</h2>
          <TunnelStatusBadge state={status?.tunnel_state ?? "unknown"} />
        </div>
        <div
          style={{
            display: "flex",
            gap: "var(--space-6)",
            color: "var(--color-text-secondary)",
            fontSize: "0.8125rem",
            fontFamily: "var(--font-code)",
          }}
        >
          {status && (
            <>
              <span>Strategy: {status.strategy}</span>
              <span>Uptime: {formatUptime(status.uptime_s)}</span>
              <span>Session: {status.session_id}</span>
            </>
          )}
        </div>
      </div>

      {/* Throughput chart */}
      <section>
        <h3
          style={{
            fontSize: "0.875rem",
            fontWeight: 600,
            color: "var(--color-text-secondary)",
            marginBottom: "var(--space-2)",
          }}
        >
          Throughput
        </h3>
        <ThroughputChart sample={throughputSample} width={640} height={200} />
        {!wsConnected && (
          <p
            style={{
              fontSize: "0.75rem",
              color: "var(--color-warning)",
              marginTop: "var(--space-1)",
            }}
          >
            WebSocket disconnected — reconnecting...
          </p>
        )}
      </section>

      {/* Total transfer */}
      {stats && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "var(--space-4)",
          }}
        >
          <StatCard label="Total TX" value={formatBytes(stats.total_tx_bytes)} color="var(--color-primary)" />
          <StatCard label="Total RX" value={formatBytes(stats.total_rx_bytes)} color="var(--color-secondary)" />
        </div>
      )}

      {/* Per-interface bandwidth bars */}
      {stats && stats.interfaces.length > 0 && (
        <section>
          <h3
            style={{
              fontSize: "0.875rem",
              fontWeight: 600,
              color: "var(--color-text-secondary)",
              marginBottom: "var(--space-3)",
            }}
          >
            Interfaces
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
            {stats.interfaces.map((iface) => (
              <InterfaceBandwidthBar key={iface.name} iface={iface} maxBytes={Math.max(stats.total_tx_bytes, stats.total_rx_bytes, 1)} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

// ---------- Sub-components ----------

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div
      style={{
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: "var(--radius)",
        padding: "var(--space-4)",
      }}
    >
      <div
        style={{
          fontSize: "0.75rem",
          color: "var(--color-text-muted)",
          marginBottom: "var(--space-1)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: "1.5rem",
          fontWeight: 700,
          fontFamily: "var(--font-code)",
          color,
        }}
      >
        {value}
      </div>
    </div>
  );
}

function InterfaceBandwidthBar({
  iface,
  maxBytes,
}: {
  iface: StatsInterface;
  maxBytes: number;
}) {
  const txPct = maxBytes > 0 ? (iface.tx_bytes / maxBytes) * 100 : 0;
  const rxPct = maxBytes > 0 ? (iface.rx_bytes / maxBytes) * 100 : 0;

  return (
    <div
      style={{
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: "var(--radius)",
        padding: "var(--space-3) var(--space-4)",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "var(--space-2)",
        }}
      >
        <span style={{ fontWeight: 600, fontSize: "0.875rem" }}>{iface.name}</span>
        <span
          style={{
            fontSize: "0.75rem",
            fontFamily: "var(--font-code)",
            color: "var(--color-text-secondary)",
          }}
        >
          RTT {(iface.rtt_us / 1000).toFixed(1)}ms
          {" / "}
          Loss {iface.loss_pct.toFixed(1)}%
          {" / "}
          Jitter {(iface.jitter_us / 1000).toFixed(1)}ms
        </span>
      </div>

      {/* TX bar */}
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", marginBottom: 4 }}>
        <span
          style={{
            fontSize: "0.6875rem",
            color: "var(--color-primary)",
            width: 20,
            fontWeight: 600,
          }}
        >
          TX
        </span>
        <div
          style={{
            flex: 1,
            height: 6,
            background: "var(--color-surface-elev)",
            borderRadius: 3,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${Math.min(txPct, 100)}%`,
              height: "100%",
              background: "var(--color-primary)",
              borderRadius: 3,
              transition: "width 0.3s ease",
            }}
          />
        </div>
        <span
          style={{
            fontSize: "0.6875rem",
            fontFamily: "var(--font-code)",
            color: "var(--color-text-muted)",
            width: 72,
            textAlign: "right",
          }}
        >
          {formatBytes(iface.tx_bytes)}
        </span>
      </div>

      {/* RX bar */}
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
        <span
          style={{
            fontSize: "0.6875rem",
            color: "var(--color-secondary)",
            width: 20,
            fontWeight: 600,
          }}
        >
          RX
        </span>
        <div
          style={{
            flex: 1,
            height: 6,
            background: "var(--color-surface-elev)",
            borderRadius: 3,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${Math.min(rxPct, 100)}%`,
              height: "100%",
              background: "var(--color-secondary)",
              borderRadius: 3,
              transition: "width 0.3s ease",
            }}
          />
        </div>
        <span
          style={{
            fontSize: "0.6875rem",
            fontFamily: "var(--font-code)",
            color: "var(--color-text-muted)",
            width: 72,
            textAlign: "right",
          }}
        >
          {formatBytes(iface.rx_bytes)}
        </span>
      </div>
    </div>
  );
}
