import { useEffect, useMemo, useState } from "react";
import Header from "./components/Header";
import ReplayStatus from "./components/ReplayStatus";
import ScoreGauge from "./components/ScoreGauge";
import AlertTimeline from "./components/AlertTimeline";
import ArchitectureDiagram from "./components/ArchitectureDiagram";
import CarsView from "./components/CarsView";
import { CanIdPanel, SimulatedResponsePanel, RoutingPanel } from "./components/DetailPanels";
import { buildMockRun, CAPTURE_META } from "./data/mockRun";
import { ESCALATION_QUALITY } from "./data/escalationQuality";
import { connectLiveFeed } from "./data/liveFeed";
import { useReplay } from "./utils/useReplay";
import { isInEscalationBand } from "./utils/escalation";
import "./App.css";

const DATA_SOURCE = "live"; // "mock" (data/mockRun.js) or "live" (data/liveFeed.js, real v2 Defender output)
const TABS = [
  { id: "kpi", label: "KPIs" },
  { id: "cars", label: "Fleet view" },
];

export default function App() {
  const mockRun = useMemo(() => buildMockRun(240), []);
  const [live, setLive] = useState({ status: DATA_SOURCE === "live" ? "loading" : "idle" });

  useEffect(() => {
    if (DATA_SOURCE !== "live") return;
    let cancelled = false;
    connectLiveFeed()
      .then(({ run, meta }) => {
        if (!cancelled) setLive({ status: "ready", run, meta });
      })
      .catch((error) => {
        if (!cancelled) setLive({ status: "error", error });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const run = DATA_SOURCE === "live" ? live.run ?? [] : mockRun;
  const meta = DATA_SOURCE === "live" ? live.meta ?? CAPTURE_META : CAPTURE_META;
  const replay = useReplay(run, { intervalMs: 300 });
  const [attackAction, setAttackAction] = useState("SIMULATED_ALERT");
  const [tab, setTab] = useState("kpi");

  if (DATA_SOURCE === "live" && live.status !== "ready") {
    return (
      <div className="app-shell">
        <Header modelVersion="–" dataSource={DATA_SOURCE} />
        <main className="dashboard-grid dashboard-grid-single">
          <p className="hint" role="status">
            {live.status === "error"
              ? `Could not load the real feed: ${live.error.message}`
              : "Loading real Defender output…"}
          </p>
        </main>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <Header modelVersion={meta.modelVersion} dataSource={DATA_SOURCE} />

      <ArchitectureDiagram output={replay.current} attackAction={attackAction} />

      <nav className="tab-row" role="tablist" aria-label="Dashboard view">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`tab-btn ${tab === t.id ? "tab-btn-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "kpi" && (
        <main className="dashboard-grid">
          <ReplayStatus
            captureId={meta.captureId}
            index={replay.index}
            total={replay.total}
            isPlaying={replay.isPlaying}
            speed={replay.speed}
            onPlay={replay.play}
            onPause={replay.pause}
            onReset={replay.reset}
            onSpeed={replay.setSpeed}
          />

          <ScoreGauge output={replay.current} />

          <CanIdPanel output={replay.current} />

          <SimulatedResponsePanel
            output={replay.current}
            attackAction={attackAction}
            onAttackActionChange={setAttackAction}
          />

          <RoutingPanel
            output={replay.current}
            escalated={isInEscalationBand(replay.current, meta.escalationBandHalfWidth)}
            quality={ESCALATION_QUALITY}
          />

          <AlertTimeline history={replay.history} />
        </main>
      )}

      {tab === "cars" && (
        <main className="dashboard-grid dashboard-grid-single">
          <CarsView output={replay.current} attackAction={attackAction} />
          <ReplayStatus
            captureId={meta.captureId}
            index={replay.index}
            total={replay.total}
            isPlaying={replay.isPlaying}
            speed={replay.speed}
            onPlay={replay.play}
            onPause={replay.pause}
            onReset={replay.reset}
            onSpeed={replay.setSpeed}
          />
        </main>
      )}

      <footer className="app-footer hint">
        Software simulation for the SJSU Edge AI Hackathon demo &middot; EdgeGuard, Secure AI track
      </footer>
    </div>
  );
}
