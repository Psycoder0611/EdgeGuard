// Current attack_score vs. the fixed threshold. This is a score, not a
// calibrated probability unless calibration is shown (see shared/schemas.py
// and defender/README.md) -- the label says so explicitly rather than
// implying a probability.

export default function ScoreGauge({ output }) {
  if (!output) return null;
  const { attack_score: score, threshold, decision } = output;
  const pct = Math.round(score * 1000) / 10;
  const thresholdPct = Math.round(threshold * 1000) / 10;
  const thresholdLabelPct = Math.min(Math.max(thresholdPct, 9), 91); // keep the label on-card; the tick stays exact
  const isAttack = decision === "ATTACK";

  return (
    <section className="card score-gauge">
      <div className="card-head">
        <h2>Attack score</h2>
        <span className={`status-badge ${isAttack ? "status-critical" : "status-good"}`}>
          {isAttack ? "ATTACK" : "ACCEPT"}
        </span>
      </div>

      <div className="score-figure mono" aria-live="polite">
        {score.toFixed(3)}
        <span className="score-figure-unit">/ 1.000</span>
      </div>
      <p className="hint">Score, not a calibrated probability.</p>

      <div className="gauge-wrap">
        <div
          className="gauge-threshold-label mono"
          style={{ left: `${thresholdLabelPct}%` }}
        >
          threshold {threshold.toFixed(3)}
        </div>
        <div className="gauge-track" aria-hidden="true">
          <div
            className={`gauge-fill ${isAttack ? "gauge-fill-critical" : "gauge-fill-good"}`}
            style={{ width: `${pct}%` }}
          />
          <div className="gauge-threshold" style={{ left: `${thresholdPct}%` }} />
        </div>
        <div className="gauge-scale">
          <span>0.0</span>
          <span>1.0</span>
        </div>
      </div>
    </section>
  );
}
