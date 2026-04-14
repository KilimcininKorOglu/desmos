/**
 * TOML configuration editor.
 *
 * A textarea-based editor that validates TOML syntax client-side
 * before allowing submission. Sends `PUT /api/v1/config` with the
 * raw TOML body.
 *
 * Client-side validation: checks for basic TOML structure (brackets
 * balance, no obvious syntax errors). Full validation happens
 * server-side.
 */

import { useCallback, useState } from "react";
import { apiFetch } from "../api";

interface TomlEditorProps {
  initialValue: string;
  onSaved?: () => void;
}

/** Basic client-side TOML validation. */
function validateToml(toml: string): string | null {
  const lines = toml.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    // Skip empty lines and comments.
    if (line === "" || line.startsWith("#")) continue;

    // Check table headers have matching brackets.
    if (line.startsWith("[")) {
      const open = (line.match(/\[/g) ?? []).length;
      const close = (line.match(/\]/g) ?? []).length;
      if (open !== close) {
        return `Line ${i + 1}: unbalanced brackets in table header`;
      }
    }

    // Check key-value lines have an = sign (unless it's a table header).
    if (!line.startsWith("[") && !line.includes("=")) {
      return `Line ${i + 1}: expected key = value`;
    }
  }
  return null;
}

export function TomlEditor({ initialValue, onSaved }: TomlEditorProps) {
  const [value, setValue] = useState(initialValue);
  const [error, setError] = useState<string | null>(null);
  const [serverError, setServerError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newVal = e.target.value;
    setValue(newVal);
    setSaved(false);
    setServerError(null);

    // Validate on every change.
    const err = validateToml(newVal);
    setError(err);
  }, []);

  async function handleSave() {
    // Re-validate before submit.
    const err = validateToml(value);
    if (err) {
      setError(err);
      return;
    }

    setSaving(true);
    setServerError(null);
    try {
      await apiFetch("/api/v1/config", {
        method: "PUT",
        body: value,
        headers: { "Content-Type": "application/toml" },
      });
      setSaved(true);
      onSaved?.();
    } catch (e) {
      setServerError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  const hasError = error !== null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
      <textarea
        value={value}
        onChange={handleChange}
        spellCheck={false}
        style={{
          width: "100%",
          minHeight: 300,
          padding: "var(--space-3)",
          fontFamily: "var(--font-code)",
          fontSize: "0.8125rem",
          lineHeight: 1.6,
          background: "var(--color-surface)",
          color: "var(--color-text)",
          border: `1px solid ${hasError ? "var(--color-error)" : "var(--color-border)"}`,
          borderRadius: "var(--radius)",
          resize: "vertical",
          outline: "none",
          tabSize: 2,
        }}
      />

      {error && (
        <p style={{ color: "var(--color-error)", fontSize: "0.75rem" }}>
          {error}
        </p>
      )}

      {serverError && (
        <p style={{ color: "var(--color-error)", fontSize: "0.75rem" }}>
          Server: {serverError}
        </p>
      )}

      {saved && !serverError && (
        <p style={{ color: "var(--color-success)", fontSize: "0.75rem" }}>
          Configuration saved and applied.
        </p>
      )}

      <div>
        <button
          onClick={handleSave}
          disabled={hasError || saving}
          style={{
            padding: "var(--space-2) var(--space-4)",
            borderRadius: "var(--radius)",
            border: "none",
            background: hasError ? "var(--color-surface-elev)" : "var(--color-primary)",
            color: hasError ? "var(--color-text-muted)" : "#fff",
            fontSize: "0.8125rem",
            fontWeight: 600,
            cursor: hasError || saving ? "not-allowed" : "pointer",
          }}
        >
          {saving ? "Saving..." : "Save Configuration"}
        </button>
      </div>
    </div>
  );
}
