// Compact replay control bar: play/pause, reset, position, scrubbable
// progress and speed, all on one small row.
export default function ReplayStatus({ captureId, index, total, isPlaying, speed, onPlay, onPause, onReset, onSpeed, onSeek }) {
  function scrub(e) {
    if (!onSeek || !total) return;
    const rect = e.currentTarget.getBoundingClientRect();
    onSeek(((e.clientX - rect.left) / rect.width) * (total - 1));
  }
  const pct = total ? Math.round(((index + 1) / total) * 100) : 0;

  return (
    <div className="replay-bar" role="group" aria-label="Replay controls">
      <button
        onClick={isPlaying ? onPause : onPlay}
        className="icon-btn icon-btn-primary"
        aria-label={isPlaying ? "Pause" : "Play"}
        title={isPlaying ? "Pause" : "Play"}
      >
        {isPlaying ? (
          <svg viewBox="0 0 16 16" width="14" height="14"><rect x="3" y="2" width="3.5" height="12" rx="1" /><rect x="9.5" y="2" width="3.5" height="12" rx="1" /></svg>
        ) : (
          <svg viewBox="0 0 16 16" width="14" height="14"><path d="M4 2.5 L13.5 8 L4 13.5 Z" /></svg>
        )}
      </button>
      <button onClick={onReset} className="icon-btn" aria-label="Reset" title="Reset">
        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
          <path d="M3 8 A5 5 0 1 0 5 4" /><path d="M2.5 2.5 V5.5 H5.5" />
        </svg>
      </button>

      <span className="replay-pos mono">
        {captureId} &middot; {index + 1}/{total}
      </span>

      <div
        className="progress-track progress-scrub"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        title="Click to jump"
        onClick={scrub}
      >
        <div className="progress-fill" style={{ width: `${pct}%` }} />
      </div>

      <div className="speed-group" aria-label="Playback speed">
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
  );
}
