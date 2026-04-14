/**
 * Desmos Web UI — root application shell.
 *
 * Renders a minimal layout with the current page content.
 * Navigation between pages will be added in later tasks;
 * for now the Dashboard is the only page.
 */

import { Dashboard } from "./pages/Dashboard";

export function App() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        minHeight: "100dvh",
      }}
    >
      {/* Header */}
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "var(--space-3) var(--space-6)",
          borderBottom: "1px solid var(--color-border)",
          background: "var(--color-surface)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
          <span
            style={{
              fontWeight: 700,
              fontSize: "1.125rem",
              color: "var(--color-primary)",
              letterSpacing: "-0.02em",
            }}
          >
            Desmos
          </span>
          <span
            style={{
              fontSize: "0.6875rem",
              color: "var(--color-text-muted)",
              fontFamily: "var(--font-code)",
            }}
          >
            bond every link
          </span>
        </div>
      </header>

      {/* Main content */}
      <main
        style={{
          flex: 1,
          padding: "var(--space-6)",
          maxWidth: 960,
          width: "100%",
          margin: "0 auto",
        }}
      >
        <Dashboard />
      </main>
    </div>
  );
}
