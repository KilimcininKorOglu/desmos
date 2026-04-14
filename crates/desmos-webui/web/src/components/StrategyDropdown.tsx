/**
 * Bonding strategy dropdown.
 *
 * Sends `PUT /api/v1/bonding/strategy` on selection change.
 * Valid strategies: round-robin, weighted, latency-adaptive, redundant.
 */

import { useState } from "react";
import { apiPut } from "../api";

const STRATEGIES = [
  { value: "round-robin", label: "Round-Robin" },
  { value: "weighted", label: "Weighted" },
  { value: "latency-adaptive", label: "Latency-Adaptive" },
  { value: "redundant", label: "Redundant" },
] as const;

interface StrategyDropdownProps {
  current: string;
  onChanged?: (strategy: string) => void;
}

export function StrategyDropdown({ current, onChanged }: StrategyDropdownProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const strategy = e.target.value;
    if (strategy === current) return;

    setBusy(true);
    setError(null);
    try {
      await apiPut("/api/v1/bonding/strategy", { strategy });
      onChanged?.(strategy);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
      <label
        htmlFor="strategy-select"
        style={{
          fontSize: "0.8125rem",
          fontWeight: 600,
          color: "var(--color-text-secondary)",
        }}
      >
        Strategy
      </label>
      <select
        id="strategy-select"
        value={current}
        onChange={handleChange}
        disabled={busy}
        style={{
          padding: "var(--space-1) var(--space-3)",
          borderRadius: "var(--radius)",
          border: "1px solid var(--color-border)",
          background: "var(--color-surface-elev)",
          color: "var(--color-text)",
          fontSize: "0.8125rem",
          fontFamily: "var(--font-code)",
          cursor: busy ? "wait" : "pointer",
          outline: "none",
        }}
      >
        {STRATEGIES.map((s) => (
          <option key={s.value} value={s.value}>
            {s.label}
          </option>
        ))}
      </select>
      {error && (
        <span style={{ color: "var(--color-error)", fontSize: "0.75rem" }}>
          {error}
        </span>
      )}
    </div>
  );
}
