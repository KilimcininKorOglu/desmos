/**
 * Canvas-based real-time throughput chart.
 *
 * Renders a rolling 60-second line chart of tx/rx bytes per second.
 * Intended to be driven by the `/api/v1/ws/stats` WebSocket stream
 * at >= 1 Hz.
 *
 * Zero external dependencies — pure Canvas 2D API.
 */

import { useCallback, useEffect, useRef } from "react";

/** A single throughput sample. */
export interface ThroughputSample {
  /** Transmit bytes per second. */
  txBps: number;
  /** Receive bytes per second. */
  rxBps: number;
}

interface ThroughputChartProps {
  /** Most recent throughput sample (append on each render). */
  sample: ThroughputSample | null;
  /** Chart width in CSS pixels.  @default 640 */
  width?: number;
  /** Chart height in CSS pixels.  @default 200 */
  height?: number;
  /** Maximum number of data points to retain.  @default 60 */
  maxPoints?: number;
}

/** Format bytes/s as a human-readable string. */
function formatRate(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} GB/s`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} MB/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} KB/s`;
  return `${bps.toFixed(0)} B/s`;
}

export function ThroughputChart({
  sample,
  width = 640,
  height = 200,
  maxPoints = 60,
}: ThroughputChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const samplesRef = useRef<ThroughputSample[]>([]);

  // Append new sample when it changes.
  useEffect(() => {
    if (!sample) return;
    const arr = samplesRef.current;
    arr.push(sample);
    if (arr.length > maxPoints) {
      arr.splice(0, arr.length - maxPoints);
    }
  }, [sample, maxPoints]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const dpr = window.devicePixelRatio || 1;
    const w = width;
    const h = height;

    // Resize canvas backing store for crisp rendering.
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr;
      canvas.height = h * dpr;
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const samples = samplesRef.current;
    const padTop = 24;
    const padBottom = 20;
    const padLeft = 56;
    const padRight = 12;
    const plotW = w - padLeft - padRight;
    const plotH = h - padTop - padBottom;

    // Clear.
    ctx.clearRect(0, 0, w, h);

    // Determine Y scale from data.
    let maxVal = 1024; // minimum 1 KB/s scale
    for (const s of samples) {
      if (s.txBps > maxVal) maxVal = s.txBps;
      if (s.rxBps > maxVal) maxVal = s.rxBps;
    }
    // Round up to a nice number.
    const magnitude = 10 ** Math.floor(Math.log10(maxVal));
    maxVal = Math.ceil(maxVal / magnitude) * magnitude;

    // Grid lines.
    ctx.strokeStyle = "var(--color-border)";
    ctx.lineWidth = 0.5;
    const gridSteps = 4;
    for (let i = 0; i <= gridSteps; i++) {
      const y = padTop + (plotH * i) / gridSteps;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(padLeft + plotW, y);
      ctx.stroke();
    }

    // Y-axis labels.
    ctx.fillStyle = getComputedStyle(canvas).getPropertyValue("--color-text-muted").trim() || "#64748B";
    ctx.font = "10px system-ui, sans-serif";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (let i = 0; i <= gridSteps; i++) {
      const y = padTop + (plotH * i) / gridSteps;
      const val = maxVal * (1 - i / gridSteps);
      ctx.fillText(formatRate(val), padLeft - 6, y);
    }

    // Nothing to plot yet.
    if (samples.length < 2) {
      ctx.fillStyle = getComputedStyle(canvas).getPropertyValue("--color-text-muted").trim() || "#64748B";
      ctx.font = "12px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText("Waiting for data...", w / 2, h / 2);
      return;
    }

    // Draw lines.
    const drawLine = (color: string, getValue: (s: ThroughputSample) => number) => {
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.lineJoin = "round";
      ctx.beginPath();
      for (let i = 0; i < samples.length; i++) {
        const x = padLeft + (plotW * i) / (maxPoints - 1);
        const val = getValue(samples[i]!);
        const y = padTop + plotH * (1 - val / maxVal);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
    };

    // TX = primary (teal), RX = secondary (cyan).
    const txColor = getComputedStyle(canvas).getPropertyValue("--color-primary").trim() || "#14B8A6";
    const rxColor = getComputedStyle(canvas).getPropertyValue("--color-secondary").trim() || "#06B6D4";

    drawLine(txColor, (s) => s.txBps);
    drawLine(rxColor, (s) => s.rxBps);

    // Legend.
    ctx.font = "11px system-ui, sans-serif";
    ctx.textAlign = "left";
    ctx.textBaseline = "top";

    ctx.fillStyle = txColor;
    ctx.fillRect(padLeft, 4, 10, 10);
    ctx.fillStyle = getComputedStyle(canvas).getPropertyValue("--color-text-secondary").trim() || "#94A3B8";
    ctx.fillText("TX", padLeft + 14, 3);

    ctx.fillStyle = rxColor;
    ctx.fillRect(padLeft + 48, 4, 10, 10);
    ctx.fillStyle = getComputedStyle(canvas).getPropertyValue("--color-text-secondary").trim() || "#94A3B8";
    ctx.fillText("RX", padLeft + 62, 3);
  }, [width, height, maxPoints]);

  // Redraw on every animation frame for smooth updates.
  useEffect(() => {
    let rafId: number;
    function loop() {
      draw();
      rafId = requestAnimationFrame(loop);
    }
    rafId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafId);
  }, [draw]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        width,
        height,
        display: "block",
        borderRadius: "var(--radius)",
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
      }}
    />
  );
}
