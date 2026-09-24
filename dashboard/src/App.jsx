import { useMemo, useState } from "react";
import Header from "./components/Header";
import ReplayStatus from "./components/ReplayStatus";
import ScoreGauge from "./components/ScoreGauge";
import AlertTimeline from "./components/AlertTimeline";
import ArchitectureDiagram from "./components/ArchitectureDiagram";
import CarsView from "./components/CarsView";
import { CanIdPanel, SimulatedResponsePanel, RoutingPanel } from "./components/DetailPanels";
import { buildMockRun, CAPTURE_META } from "./data/mockRun";
import { useReplay } from "./utils/useReplay";
import "./App.css";

const DATA_SOURCE = "mock"; // flip to "live" once connectLiveFeed() (data/liveFeed.js) is wired up
const TABS = [
  { id: "kpi", label: "KPIs" },
  { id: "cars", label: "Fleet view" },
];

export default function App() {
  const run = useMemo(() => buildMockRun(240), []);
  const replay = useReplay(run, { intervalMs: 300 });
  const [attackAction, setAttackAction] = useState("SIMULATED_ALERT");
  const [tab, setTab] = useState("kpi");

  return (
    <div className="app-shell">
      <Header modelVersion={CAPTURE_META.modelVersion} dataSource={DATA_SOURCE} />

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
            captureId={CAPTURE_META.captureId}
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

          <RoutingPanel />

          <AlertTimeline history={replay.history} />
        </main>
      )}

      {tab === "cars" && (
        <main className="dashboard-grid dashboard-grid-single">
          <CarsView output={replay.current} attackAction={attackAction} />
          <ReplayStatus
            captureId={CAPTURE_META.captureId}
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
