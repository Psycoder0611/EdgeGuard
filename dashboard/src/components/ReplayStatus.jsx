export default function ReplayStatus({ captureId, index, total, isPlaying, speed, onPlay, onPause, onReset, onSpeed }) {
  const pct = total ? Math.round(((index + 1) / total) * 100) : 0;

  return (
    <section className="card replay-status">
      <div className="card-head">
        <h2>Replay status</h2>
        <span className={`pill ${isPlaying ? "pill-live" : "pill-idle"}`}>
          {isPlaying ? "Replaying" : "Paused"}
        </span>
      </div>

      <div className="replay-meta">
        <div>
          <span className="label">Capture</span>
          <span className="value mono">{captureId}</span>
        </div>
        <div>
          <span className="label">Window</span>
          <span className="value mono">{index + 1} / {total}</span>
        </div>
      </div>

      <div className="progress-track" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <div className="progress-fill" style={{ width: `${pct}%` }} />
      </div>

      <div className="replay-controls">
        <button onClick={isPlaying ? onPause : onPlay} className="btn btn-primary">
          {isPlaying ? "Pause" : "Play"}
        </button>
        <button onClick={onReset} className="btn">Reset</button>
        <div className="speed-group" role="group" aria-label="Playback speed">
          {[1, 2, 4].map((s) => (
            <button
              key={s}
              className={`btn btn-chip ${speed === s ? "btn-chip-active" : ""}`}
              onClick={() => onSpeed(s)}
            >
              {s}x
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
