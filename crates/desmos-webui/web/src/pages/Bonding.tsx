/**
 * Bonding configuration page.
 *
 * Strategy dropdown for hot-switching between bonding algorithms.
 * Weight sliders for per-interface weight tuning (visible when
 * strategy is "weighted").
 * Displays link count stats from GET /api/v1/bonding.
 */

import { useCallback, useState } from "react";
import { useFetch } from "../hooks/useFetch";
import { StrategyDropdown } from "../components/StrategyDropdown";
import { WeightSlider } from "../components/WeightSlider";
import type { ApiResponse } from "../api";

interface BondingData {
  strategy: string;
  active_links: number;
  degraded_links: number;
  dead_links: number;
}

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

export function Bonding() {
  const { data: bondingResp, loading } = useFetch<ApiResponse<BondingData>>("/api/v1/bonding");
  const { data: statusResp } = useFetch<ApiResponse<StatusData>>("/api/v1/status");

  const [strategy, setStrategy] = useState<string | null>(null);

  // Use local override if user changed, else API value.
  const currentStrategy = strategy ?? bondingResp?.data.strategy ?? "round-robin";
  const bonding = bondingResp?.data;
  const interfaces = statusResp?.data.interfaces ?? [];

  const handleStrategyChanged = useCallback((newStrategy: string) => {
    setStrategy(newStrategy);
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1.25rem", fontWeight: 700 }}>Bonding</h2>

      {loading && (
        <p style={{ color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
          Loading...
        </p>
      )}

      {/* Strategy selector */}
      <section
        style={{
          background: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius)",
          padding: "var(--space-4)",
          display: "flex",
          flexDirection: "column",
          gap: "var(--space-4)",
        }}
      >
        <StrategyDropdown current={currentStrategy} onChanged={handleStrategyChanged} />

        {/* Link stats */}
        {bonding && (
          <div
            style={{
              display: "flex",
              gap: "var(--space-6)",
              fontSize: "0.8125rem",
              fontFamily: "var(--font-code)",
            }}
          >
            <LinkStat label="Active" count={bonding.active_links} color="var(--color-success)" />
            <LinkStat label="Degraded" count={bonding.degraded_links} color="var(--color-warning)" />
            <LinkStat label="Dead" count={bonding.dead_links} color="var(--color-error)" />
          </div>
        )}
      </section>

      {/* Weight sliders (visible for weighted strategy) */}
      {currentStrategy === "weighted" && interfaces.length > 0 && (
        <section
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius)",
            padding: "var(--space-4)",
            display: "flex",
            flexDirection: "column",
            gap: "var(--space-3)",
          }}
        >
          <h3
            style={{
              fontSize: "0.875rem",
              fontWeight: 600,
              color: "var(--color-text-secondary)",
              marginBottom: "var(--space-1)",
            }}
          >
            Interface Weights
          </h3>
          {interfaces.map((iface) => (
            <WeightSlider
              key={iface.name}
              interfaceName={iface.name}
              initialWeight={100}
            />
          ))}
        </section>
      )}

      {/* Empty state for weighted without interfaces */}
      {currentStrategy === "weighted" && interfaces.length === 0 && (
        <p style={{ color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
          No interfaces available for weight configuration.
        </p>
      )}
    </div>
  );
}

function LinkStat({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color: string;
}) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          backgroundColor: color,
          flexShrink: 0,
        }}
      />
      <span style={{ color: "var(--color-text-secondary)" }}>{label}:</span>
      <span style={{ fontWeight: 600, color }}>{count}</span>
    </div>
  );
}
