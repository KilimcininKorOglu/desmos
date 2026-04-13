import { useFetch } from "./hooks/useFetch";

interface HealthResponse {
  status: string;
  version: string;
  tunnel_state: string;
  uptime_s: number;
}

export function App() {
  const { data, error, loading } = useFetch<HealthResponse>("/api/v1/health");

  return (
    <div
      style={{
        padding: "var(--space-8)",
        maxWidth: "800px",
        margin: "0 auto",
      }}
    >
      <h1
        style={{
          color: "var(--color-primary)",
          marginBottom: "var(--space-4)",
          fontWeight: 700,
        }}
      >
        Desmos
      </h1>
      <p
        style={{
          color: "var(--color-text-secondary)",
          marginBottom: "var(--space-8)",
        }}
      >
        Bond every link.
      </p>

      {loading && <p style={{ color: "var(--color-text-muted)" }}>Loading...</p>}

      {error && (
        <p style={{ color: "var(--color-error)" }}>
          Connection error: {error}
        </p>
      )}

      {data && (
        <div
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius)",
            padding: "var(--space-6)",
          }}
        >
          <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "var(--space-2) var(--space-4)" }}>
            <dt style={{ color: "var(--color-text-secondary)" }}>Status</dt>
            <dd>{data.status}</dd>
            <dt style={{ color: "var(--color-text-secondary)" }}>Version</dt>
            <dd style={{ fontFamily: "var(--font-code)" }}>{data.version}</dd>
            <dt style={{ color: "var(--color-text-secondary)" }}>Tunnel</dt>
            <dd>{data.tunnel_state}</dd>
            <dt style={{ color: "var(--color-text-secondary)" }}>Uptime</dt>
            <dd>{data.uptime_s}s</dd>
          </dl>
        </div>
      )}
    </div>
  );
}
