/**
 * Live log stream component.
 *
 * Subscribes to `/api/v1/ws/logs` with an optional `?level=` filter.
 * Renders a scrollable, monospace log viewer with level-colored badges.
 * Auto-scrolls to bottom unless the user has scrolled up.
 */

import { useEffect, useRef, useState } from "react";
import { useWsStream } from "../hooks/useWsStream";

interface LogEntry {
  timestamp_us: number;
  level: string;
  target: string;
  message: string;
}

interface WsLogMessage {
  data: LogEntry;
}

interface LogStreamProps {
  level: string;
  maxEntries?: number;
}

const LEVEL_COLORS: Record<string, string> = {
  error: "var(--color-error)",
  warn: "var(--color-warning)",
  info: "var(--color-info)",
  debug: "var(--color-text-muted)",
  trace: "var(--color-text-muted)",
};

function formatTimestamp(us: number): string {
  const ms = us / 1000;
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const mss = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${mss}`;
}

export function LogStream({ level, maxEntries = 500 }: LogStreamProps) {
  const wsPath = level ? `/api/v1/ws/logs?level=${level}` : "/api/v1/ws/logs";
  const { latest, connected } = useWsStream<WsLogMessage>(wsPath);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);

  // Append new log entry when received.
  useEffect(() => {
    if (!latest) return;
    setEntries((prev) => {
      const next = [...prev, latest.data];
      if (next.length > maxEntries) {
        return next.slice(next.length - maxEntries);
      }
      return next;
    });
  }, [latest, maxEntries]);

  // Auto-scroll to bottom.
  useEffect(() => {
    const el = containerRef.current;
    if (el && autoScrollRef.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [entries]);

  // Track scroll position to disable auto-scroll when user scrolls up.
  function handleScroll() {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    autoScrollRef.current = atBottom;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)" }}>
      {!connected && (
        <p
          style={{
            fontSize: "0.75rem",
            color: "var(--color-warning)",
          }}
        >
          WebSocket disconnected — reconnecting...
        </p>
      )}

      <div
        ref={containerRef}
        onScroll={handleScroll}
        style={{
          background: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius)",
          padding: "var(--space-3)",
          height: 400,
          overflowY: "auto",
          fontFamily: "var(--font-code)",
          fontSize: "0.75rem",
          lineHeight: 1.8,
        }}
      >
        {entries.length === 0 && (
          <p style={{ color: "var(--color-text-muted)" }}>
            Waiting for log entries...
          </p>
        )}
        {entries.map((entry, i) => (
          <div key={i} style={{ display: "flex", gap: "var(--space-2)" }}>
            <span style={{ color: "var(--color-text-muted)", flexShrink: 0 }}>
              {formatTimestamp(entry.timestamp_us)}
            </span>
            <span
              style={{
                color: LEVEL_COLORS[entry.level] ?? "var(--color-text)",
                fontWeight: 600,
                minWidth: 40,
                flexShrink: 0,
                textTransform: "uppercase",
              }}
            >
              {entry.level}
            </span>
            <span style={{ color: "var(--color-text-secondary)", flexShrink: 0 }}>
              {entry.target}
            </span>
            <span style={{ color: "var(--color-text)" }}>
              {entry.message}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
