/**
 * Tunnel status badge.
 *
 * Displays a colored pill indicating tunnel state:
 * up (green), connecting (blue), degraded (amber), down (red), unknown (muted).
 */

const stateColors: Record<string, string> = {
  up: "var(--color-success)",
  connecting: "var(--color-info)",
  degraded: "var(--color-warning)",
  down: "var(--color-error)",
  unknown: "var(--color-text-muted)",
};

interface TunnelStatusBadgeProps {
  state: string;
}

export function TunnelStatusBadge({ state }: TunnelStatusBadgeProps) {
  const color = stateColors[state] ?? stateColors["unknown"];
  const label = state.charAt(0).toUpperCase() + state.slice(1);

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "var(--space-2)",
        padding: "var(--space-1) var(--space-3)",
        borderRadius: "var(--radius)",
        background: "var(--color-surface-elev)",
        fontSize: "0.8125rem",
        fontWeight: 600,
        letterSpacing: "0.02em",
      }}
    >
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          backgroundColor: color,
          flexShrink: 0,
        }}
      />
      <span style={{ color }}>{label}</span>
    </span>
  );
}
