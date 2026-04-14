/**
 * Logs page.
 *
 * Live log stream via `/api/v1/ws/logs` with level filter dropdown.
 * Retains up to 500 entries client-side.
 */

import { useState } from "react";
import { LogStream } from "../components/LogStream";

const LOG_LEVELS = ["trace", "debug", "info", "warn", "error"] as const;

export function Logs() {
  const [level, setLevel] = useState<string>("info");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "var(--space-4)",
        }}
      >
        <h2 style={{ fontSize: "1.25rem", fontWeight: 700 }}>Logs</h2>

        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
          <label
            htmlFor="log-level-select"
            style={{
              fontSize: "0.8125rem",
              fontWeight: 600,
              color: "var(--color-text-secondary)",
            }}
          >
            Level
          </label>
          <select
            id="log-level-select"
            value={level}
            onChange={(e) => setLevel(e.target.value)}
            style={{
              padding: "var(--space-1) var(--space-3)",
              borderRadius: "var(--radius)",
              border: "1px solid var(--color-border)",
              background: "var(--color-surface-elev)",
              color: "var(--color-text)",
              fontSize: "0.8125rem",
              fontFamily: "var(--font-code)",
              cursor: "pointer",
              outline: "none",
            }}
          >
            {LOG_LEVELS.map((l) => (
              <option key={l} value={l}>
                {l.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
      </div>

      <LogStream level={level} maxEntries={500} />
    </div>
  );
}
