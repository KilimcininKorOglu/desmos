/**
 * Interface weight slider.
 *
 * Range 0-1000. Sends `PUT /api/v1/interfaces/:name` with `{ weight }` on change.
 * Debounces by 300ms to avoid flooding the API while dragging.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { apiPut } from "../api";

interface WeightSliderProps {
  interfaceName: string;
  initialWeight: number;
  onApplied?: (weight: number) => void;
}

export function WeightSlider({ interfaceName, initialWeight, onApplied }: WeightSliderProps) {
  const [value, setValue] = useState(initialWeight);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sync with external prop changes.
  useEffect(() => {
    setValue(initialWeight);
  }, [initialWeight]);

  const applyWeight = useCallback(
    async (weight: number) => {
      setError(null);
      try {
        await apiPut(`/api/v1/interfaces/${encodeURIComponent(interfaceName)}`, {
          weight,
        });
        onApplied?.(weight);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    },
    [interfaceName, onApplied],
  );

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const newVal = Number(e.target.value);
    setValue(newVal);

    // Debounce API call.
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      void applyWeight(newVal);
    }, 300);
  }

  // Cleanup timer on unmount.
  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "var(--space-3)",
      }}
    >
      <span
        style={{
          fontSize: "0.8125rem",
          fontWeight: 600,
          color: "var(--color-text-secondary)",
          minWidth: 80,
        }}
      >
        {interfaceName}
      </span>
      <input
        type="range"
        min={0}
        max={1000}
        step={1}
        value={value}
        onChange={handleChange}
        style={{
          flex: 1,
          accentColor: "var(--color-primary)",
          cursor: "pointer",
        }}
      />
      <span
        style={{
          fontFamily: "var(--font-code)",
          fontSize: "0.75rem",
          color: "var(--color-text)",
          minWidth: 36,
          textAlign: "right",
        }}
      >
        {value}
      </span>
      {error && (
        <span style={{ color: "var(--color-error)", fontSize: "0.6875rem" }}>
          {error}
        </span>
      )}
    </div>
  );
}
