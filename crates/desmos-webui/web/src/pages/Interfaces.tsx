/**
 * Interfaces page.
 *
 * Shows a table of all network interfaces with their link quality
 * metrics. Supports toggling enabled/disabled via PUT and live
 * stats updates via WS.
 */

import { useCallback, useState } from "react";
import { useFetch } from "../hooks/useFetch";
import { useWsStream } from "../hooks/useWsStream";
import { InterfaceTable, type InterfaceRow } from "../components/InterfaceTable";
import type { ApiResponse } from "../api";

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

export function Interfaces() {
  const { data: statusResp, loading } = useFetch<ApiResponse<StatusData>>("/api/v1/status");
  const { latest: wsStats } = useWsStream<ApiResponse<StatsData>>("/api/v1/ws/stats");
  const [refreshKey, setRefreshKey] = useState(0);

  const handleUpdated = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  // Merge status (state, enabled) + live stats (rtt, loss, jitter, bytes).
  const rows: InterfaceRow[] = (() => {
    const statusIfaces = statusResp?.data.interfaces ?? [];
    const statsIfaces = wsStats?.data.interfaces ?? [];

    // Use status as base, enrich with live stats.
    return statusIfaces.map((si) => {
      const live = statsIfaces.find((li) => li.name === si.name);
      return {
        name: si.name,
        state: si.state,
        rtt_us: live?.rtt_us ?? si.rtt_us,
        loss_pct: live?.loss_pct ?? 0,
        jitter_us: live?.jitter_us ?? 0,
        tx_bytes: live?.tx_bytes ?? 0,
        rx_bytes: live?.rx_bytes ?? 0,
        weight: 100, // TODO: wire from real config
        enabled: si.state !== "dead",
      };
    });
  })();

  // refreshKey used to force re-fetch after toggle
  void refreshKey;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1.25rem", fontWeight: 700 }}>Interfaces</h2>

      {loading && (
        <p style={{ color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
          Loading...
        </p>
      )}

      <InterfaceTable interfaces={rows} onUpdated={handleUpdated} />
    </div>
  );
}
