/**
 * Desmos Web UI — root application shell.
 *
 * Minimal hash-based routing: #dashboard (default), #interfaces, #bonding.
 * No external router dependency — uses `hashchange` event + useState.
 */

import { useEffect, useState } from "react";
import { Dashboard } from "./pages/Dashboard";
import { Interfaces } from "./pages/Interfaces";
import { Bonding } from "./pages/Bonding";

type Page = "dashboard" | "interfaces" | "bonding";

const NAV_ITEMS: { page: Page; label: string }[] = [
  { page: "dashboard", label: "Dashboard" },
  { page: "interfaces", label: "Interfaces" },
  { page: "bonding", label: "Bonding" },
];

function getPageFromHash(): Page {
  const hash = location.hash.replace("#", "");
  if (hash === "interfaces" || hash === "bonding") return hash;
  return "dashboard";
}

export function App() {
  const [page, setPage] = useState<Page>(getPageFromHash);

  useEffect(() => {
    function onHashChange() {
      setPage(getPageFromHash());
    }
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

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
          <a
            href="#dashboard"
            style={{
              fontWeight: 700,
              fontSize: "1.125rem",
              color: "var(--color-primary)",
              letterSpacing: "-0.02em",
              textDecoration: "none",
            }}
          >
            Desmos
          </a>
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

        {/* Navigation */}
        <nav style={{ display: "flex", gap: "var(--space-1)" }}>
          {NAV_ITEMS.map((item) => (
            <a
              key={item.page}
              href={`#${item.page}`}
              style={{
                padding: "var(--space-1) var(--space-3)",
                borderRadius: "var(--radius-sm)",
                fontSize: "0.8125rem",
                fontWeight: page === item.page ? 600 : 400,
                color: page === item.page ? "var(--color-primary)" : "var(--color-text-secondary)",
                background: page === item.page ? "var(--color-surface-elev)" : "transparent",
                textDecoration: "none",
                transition: "background 0.15s, color 0.15s",
              }}
            >
              {item.label}
            </a>
          ))}
        </nav>
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
        {page === "dashboard" && <Dashboard />}
        {page === "interfaces" && <Interfaces />}
        {page === "bonding" && <Bonding />}
      </main>
    </div>
  );
}
