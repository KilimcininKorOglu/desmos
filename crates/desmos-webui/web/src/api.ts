/**
 * Desmos REST API client.
 *
 * All fetch wrappers target `/api/v1/*` relative paths so the Vite
 * dev proxy and the embedded production server both work.
 */

/** Standard success envelope from the API. */
export interface ApiResponse<T> {
  data: T;
  meta: {
    request_id: string;
    generated_at_us: number;
  };
}

/** Standard error envelope from the API. */
export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  meta: {
    request_id: string;
  };
}

/** Fetch JSON from the API with Basic Auth. */
export async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const resp = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!resp.ok) {
    const body = await resp.json().catch(() => null);
    const msg =
      (body as ApiError | null)?.error?.message ?? `HTTP ${resp.status}`;
    throw new Error(msg);
  }

  return resp.json() as Promise<T>;
}

/** PUT JSON to an API endpoint. */
export async function apiPut<T>(
  path: string,
  body: unknown,
  headers?: Record<string, string>,
): Promise<T> {
  return apiFetch<T>(path, {
    method: "PUT",
    body: JSON.stringify(body),
    headers,
  });
}

/** DELETE an API resource. */
export async function apiDelete<T>(
  path: string,
  headers?: Record<string, string>,
): Promise<T> {
  return apiFetch<T>(path, { method: "DELETE", headers });
}

/**
 * Create a WebSocket connection to a Desmos WS endpoint.
 *
 * Automatically constructs the `ws://` or `wss://` URL from the
 * current page origin.
 */
export function createWs(path: string): WebSocket {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return new WebSocket(`${proto}//${location.host}${path}`);
}
