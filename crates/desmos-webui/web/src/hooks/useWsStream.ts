import { useEffect, useRef, useState } from "react";
import { createWs } from "../api";

interface UseWsStreamResult<T> {
  /** Most recent message received. */
  latest: T | null;
  /** Whether the WebSocket is currently connected. */
  connected: boolean;
  /** Last error message, if any. */
  error: string | null;
}

/**
 * Subscribe to a Desmos WebSocket stream and parse incoming JSON
 * text frames into `T`.
 *
 * Automatically reconnects with exponential backoff (1s, 2s, 4s,
 * max 30s).  Cleans up on unmount.
 *
 * @param path - WebSocket path, e.g. `/api/v1/ws/stats`
 */
export function useWsStream<T>(path: string): UseWsStreamResult<T> {
  const [latest, setLatest] = useState<T | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);

  useEffect(() => {
    let unmounted = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (unmounted) return;

      const ws = createWs(path);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setError(null);
        retryRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data as string) as T;
          setLatest(parsed);
        } catch {
          // Ignore non-JSON frames (ping/pong).
        }
      };

      ws.onerror = () => {
        setError("WebSocket error");
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        if (unmounted) return;

        // Exponential backoff: 1s, 2s, 4s, ..., max 30s.
        const delay = Math.min(1000 * 2 ** retryRef.current, 30_000);
        retryRef.current += 1;
        timer = setTimeout(connect, delay);
      };
    }

    connect();

    return () => {
      unmounted = true;
      if (timer) clearTimeout(timer);
      wsRef.current?.close();
    };
  }, [path]);

  return { latest, connected, error };
}
