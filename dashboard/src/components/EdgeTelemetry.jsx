// Live device telemetry from the local analysis server (/api/system),
// refreshed every 3 s. EdgeGuard has no language model, so there are no
// "tokens": its unit of work is a CAN frame, so throughput is frames/s.
import { useEffect, useState } from "react";
import { fetchSystem } from "../data/analyzeClient";

const POLL_MS = 3000;

const gb = (b) => (b == null ? "-" : `${(b / 1e9).toFixed(1)} GB`);
const size = (b) => (b == null ? "-" : b >= 1e9 ? gb(b) : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.round(b / 1e3)} KB`);
const pct = (v) => (v == null ? "-" : `${v.toFixed(1)}%`);

export default function EdgeTelemetry() {
  const [data, setData] = useState(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let alive = true;
    const ctrl = new AbortController();
    async function tick() {
      try {
        const d = await fetchSystem(ctrl.signal);
        if (alive) {
          setData(d);
          setOffline(false);
        }
      } catch {
        if (alive) setOffline(true);
      }
    }
    tick();
    const t = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      ctrl.abort();
      clearInterval(t);
    };
  }, []);

  if (offline || !data) {
    return (
      <section className="card edge-telemetry">
        <div className="card-head">
          <h2>Edge device</h2>
          <span className="status-badge status-disabled">{offline ? "Offline" : "Connecting"}</span>
        </div>
        <p className="hint">
          Start the analysis server to see live CPU, memory and throughput:
        </p>
        <code className="cmd">python -m uvicorn integration.analyze_server:app --host 127.0.0.1 --port 8000</code>
      </section>
    );
  }

  const { cpu, memory, gpu, model, totals, last_run: last, active } = data;
  const running = active?.running;
  const fps = running ? active.frames_per_s : last?.frames_per_s;
  const wps = running ? active.windows_per_s : last?.windows_per_s;

  return (
    <section className="card edge-telemetry">
      <div className="card-head">
        <h2>Edge device</h2>
        <span className={`status-badge ${running ? "status-warning" : "status-good"}`}>
          {running ? `Scoring ${active.name}` : "Idle"}
        </span>
      </div>

      <div className="device-banner">
        <span className="device-chip mono">{data.machine}</span>
        <div>
          <strong>{data.host}</strong>
          <span className="hint">{data.os} &middot; {cpu.cores} cores &middot; local inference</span>
        </div>
      </div>

      <div className="tele-grid">
        <Tile tone="cyan" label="CPU utilization" value={pct(cpu.system_pct)}
              sub={`EdgeGuard process ${pct(cpu.process_pct)}`} />
        <Tile tone="violet" label="Memory" value={pct(memory.pct)}
              sub={`${gb(memory.used_bytes)} / ${gb(memory.total_bytes)}`} />
        <Tile tone="blue" label="GPU"
              value={gpu.available ? pct(gpu.util_pct) : "Not used"}
              sub={gpu.available ? `${gpu.name} · Defender runs on CPU` : "Defender runs on CPU only"} />
        <Tile tone="amber" label="Frames / second" value={fps != null ? Math.round(fps).toLocaleString() : "-"}
              sub={wps != null ? `${Number(wps).toFixed(0)} windows/s · ${running ? "live" : "last run"}` : "Analyze a capture"} />
        <Tile tone="cyan" label="CAN frames processed" value={(totals.frames_processed || 0).toLocaleString()}
              sub={`${size(totals.bytes_ingested)} ingested · ${totals.captures_analyzed} capture(s)`} />
        <Tile tone="red" label="Windows scored" value={(totals.windows_scored || 0).toLocaleString()}
              sub={`${totals.attacks_flagged || 0} flagged as attack`} />
        <Tile tone="green" label="Inference latency"
              value={totals.mean_latency_ms != null ? `${totals.mean_latency_ms.toFixed(2)} ms` : "-"}
              sub={last?.p95_latency_ms != null ? `p95 ${last.p95_latency_ms} ms · per window` : "mean per window"} />
        <Tile tone="violet" label="Model" value={`${(model.bytes / 1024).toFixed(0)} KB`}
              sub={`${model.version} · pure Python, no ML runtime`} />
      </div>

      <p className="hint tele-foot">
        EdgeGuard has no language model, so it counts CAN frames instead of tokens. Updates every 3 seconds.
        {cpu.source !== "psutil" && " Install psutil for exact CPU and memory."}
      </p>
    </section>
  );
}

function Tile({ tone, label, value, sub }) {
  return (
    <div className={`kpi-tile kpi-${tone}`}>
      <span className="kpi-label">{label}</span>
      <div className="kpi-value mono">{value}</div>
      <span className="kpi-sub">{sub}</span>
    </div>
  );
}
