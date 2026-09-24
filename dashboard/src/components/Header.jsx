export default function Header({ modelVersion, dataSource }) {
  return (
    <header className="app-header">
      <div className="app-header-title">
        <span className="app-header-mark" aria-hidden="true" />
        <div>
          <h1>EdgeGuard</h1>
          <p className="hint">CAN-bus intrusion detection &middot; live demo dashboard</p>
        </div>
      </div>
      <div className="app-header-meta">
        <span className="pill pill-idle mono">model {modelVersion}</span>
        <span className={`pill ${dataSource === "mock" ? "pill-mock" : "pill-live"}`}>
          {dataSource === "mock" ? "MOCK DATA" : "LIVE"}
        </span>
      </div>
    </header>
  );
}
