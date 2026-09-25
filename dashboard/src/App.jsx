import { useEffect, useMemo, useState } from "react";
import Header from "./components/Header";
import ReplayStatus from "./components/ReplayStatus";
import ScoreGauge from "./components/ScoreGauge";
import AlertTimeline from "./components/AlertTimeline";
import ArchitectureDiagram from "./components/ArchitectureDiagram";
import CarsView from "./components/CarsView";
import KpiTiles from "./components/KpiTiles";
import ScoreChart from "./components/ScoreChart";
import UploadPanel from "./components/UploadPanel";
import EdgeTelemetry from "./components/EdgeTelemetry";
import { AttackerPanel, DefenderPanel, RoutingPanel } from "./components/DetailPanels";
import { buildMockRun, CAPTURE_META } from "./data/mockRun";
import { ESCALATION_QUALITY } from "./data/escalationQuality";
import { connectLiveFeed } from "./data/liveFeed";
import { useReplay } from "./utils/useReplay";
import { isInEscalationBand } from "./utils/escalation";
import "./App.css";

const DATA_SOURCE = "live"; // "mock" (data/mockRun.js) or "live" (data/liveFeed.js, real v2 Defender output)
const TABS = [
  { id: "cars", label: "Fleet view" },
  { id: "kpi", label: "KPIs" },
  { id: "metrics", label: "Metrics" },
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

  // An uploaded capture (scored by the local analysis server) replaces the
  // demo replay until the user switches back.
  const [upload, setUpload] = useState(null);
  const [source, setSource] = useState("demo");
  const [panelOpen, setPanelOpen] = useState(false);

  const demoRun = DATA_SOURCE === "live" ? live.run ?? [] : mockRun;
  const demoMeta = DATA_SOURCE === "live" ? live.meta ?? CAPTURE_META : CAPTURE_META;
  const run = source === "upload" && upload ? upload.run : demoRun;
  const meta = source === "upload" && upload ? upload.meta : demoMeta;
  const replay = useReplay(run, { intervalMs: 300 });
  const [attackAction, setAttackAction] = useState("SIMULATED_ALERT");
  const [tab, setTab] = useState("cars");
  // realRun.json chains several captures; show the one the current window belongs to.
  const captureId = replay.current?.window_id?.split("_")[0] ?? meta.captureId;

  if (DATA_SOURCE === "live" && live.status !== "ready") {
    return (
      <div className="app-shell">
        <Header dataSource={DATA_SOURCE} />
        <main className="dashboard-grid">
          <p className="hint" role="status">
            {live.status === "error"
              ? `Could not load the real feed: ${live.error.message}`
              : "Loading real Defender output…"}
          </p>
        </main>
      </div>
    );
  }

  function applyUpload(result) {
    setUpload(result);
    setSource("upload");
    replay.reset();
    setPanelOpen(false);
    setTab("cars");
  }

  function backToDemo() {
    setSource("demo");
    replay.reset();
  }

  const replayBar = (
    <ReplayStatus
      captureId={captureId}
      index={replay.index}
      total={replay.total}
      isPlaying={replay.isPlaying}
      speed={replay.speed}
      onPlay={replay.play}
      onPause={replay.pause}
      onReset={replay.reset}
      onSpeed={replay.setSpeed}
      onSeek={replay.seek}
    />
  );

  return (
    <div className="app-shell">
      <Header
        dataSource={DATA_SOURCE}
        sourceLabel={source === "upload" && upload ? upload.meta.fileName : null}
        onOpenUpload={() => setPanelOpen(true)}
      />

      <UploadPanel
        open={panelOpen}
        onClose={() => setPanelOpen(false)}
        onReplay={applyUpload}
        onUseDemo={backToDemo}
        source={source}
        uploadedName={upload?.meta.fileName}
      />

      <div className="toolbar">
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
        {replayBar}
      </div>

      {tab === "cars" && (
        <main className="fleet-grid">
          <CarsView output={replay.current} attackAction={attackAction} />

          <AttackerPanel output={replay.current} history={replay.history} />

          <DefenderPanel
            output={replay.current}
            history={replay.history}
            attackAction={attackAction}
            onAttackActionChange={setAttackAction}
          />

          <AlertTimeline history={replay.history} onSeek={replay.seek} />
        </main>
      )}

      {tab === "kpi" && (
        <main className="dashboard-grid">
          <ArchitectureDiagram output={replay.current} attackAction={attackAction} />
          <ScoreGauge output={replay.current} wide />
        </main>
      )}

      {tab === "metrics" && (
        <main className="metrics-grid">
          <KpiTiles
            history={replay.history}
            total={replay.total}
            bandHalfWidth={meta.escalationBandHalfWidth}
          />

          <EdgeTelemetry />

          <ScoreChart run={run} history={replay.history} index={replay.index} onSeek={replay.seek} />

          <RoutingPanel
            output={replay.current}
            escalated={isInEscalationBand(replay.current, meta.escalationBandHalfWidth)}
            quality={ESCALATION_QUALITY}
          />
        </main>
      )}

      <footer className="app-footer hint">
        Software simulation for the SJSU Edge AI Hackathon demo &middot; EdgeGuard, Secure AI track
      </footer>
    </div>
  );
}
