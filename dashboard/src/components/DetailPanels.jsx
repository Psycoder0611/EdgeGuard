import { parseEvidence } from "../utils/parseEvidence";
import { ACTIONS } from "./actionMeta";

export function CanIdPanel({ output }) {
  const { canId, stage } = parseEvidence(output?.evidence);
  return (
    <section className="card can-id-panel">
      <div className="card-head">
        <h2>Affected CAN ID</h2>
      </div>
      {canId ? (
        <>
          <div className="can-id-value mono">{canId}</div>
          <p className="hint">Parsed from evidence{stage ? ` (${stage})` : ""}. Best-effort until the team standardizes the evidence format.</p>
        </>
      ) : (
        <>
          <div className="can-id-value mono can-id-unknown">&mdash;</div>
          <p className="hint">Not stated in this window's evidence text.</p>
        </>
      )}
    </section>
  );
}

export function SimulatedResponsePanel({ output, attackAction, onAttackActionChange }) {
  const action = !output
    ? null
    : output.decision === "ATTACK"
    ? attackAction
    : "SIMULATED_FORWARD";
  const meta = action ? ACTIONS[action] : null;

  return (
    <section className="card response-panel">
      <div className="card-head">
        <h2>Simulated response</h2>
      </div>

      {meta ? (
        <span className={`status-badge ${meta.tone}`}>{meta.label}</span>
      ) : (
        <span className="hint">Waiting for first window&hellip;</span>
      )}
      <p className="hint">Software simulation only &mdash; never touches real CAN frames or ROAD files.</p>

      <div className="toggle-row">
        <span className="label">On ATTACK, use:</span>
        <div className="speed-group" role="group" aria-label="Attack action (team setting)">
          {["SIMULATED_ALERT", "SIMULATED_ISOLATION"].map((a) => (
            <button
              key={a}
              className={`btn btn-chip ${attackAction === a ? "btn-chip-active" : ""}`}
              onClick={() => onAttackActionChange(a)}
            >
              {a === "SIMULATED_ALERT" ? "Alert" : "Isolate"}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

export function RoutingPanel({ output, escalated, quality }) {
  const decided = Boolean(output);
  return (
    <section className="card routing-panel">
      <div className="card-head">
        <h2>Local / cloud routing</h2>
      </div>
      <div className="routing-row">
        <span className="status-badge status-good">LOCAL &mdash; decision made on-device, always</span>
        {decided && (
          <span
            className={`status-badge ${escalated ? "status-warning" : "status-disabled"}`}
            title={
              escalated
                ? "This window's score falls inside the calibrated uncertainty band around the threshold -- a real run would sanitize it (no raw CAN data) and send it for a cloud second opinion."
                : "This window's score is outside the uncertainty band -- the local decision is trusted on its own; no cloud call."
            }
          >
            {escalated ? "IN ESCALATION BAND — would call cloud" : "CONFIDENT — no escalation"}
          </span>
        )}
      </div>
      <p className="hint">
        The local decision is never blocked on the cloud call (part1/escalation_policy.py,
        sanitizer.py, mock_cloud_endpoint.py) &mdash; this badge shows whether THIS window
        falls inside the real calibrated band, using the same rule as a live run.
      </p>
      {quality && (
        <div className="routing-quality">
          <p className="hint">
            Measured against known labels (Red Team test path, no cloud needed &mdash;{" "}
            {quality.source}):
          </p>
          <ul className="routing-quality-list">
            <li>
              <strong>{(quality.escalationPrecision * 100).toFixed(1)}%</strong> of escalated
              windows are real local mistakes (escalation precision)
            </li>
            <li>
              <strong>{quality.escalatedFalsePositives}/{quality.localFalsePositives}</strong>{" "}
              (100%) of false alarms get escalated for review
            </li>
            <li>
              <strong>{quality.escalatedFalseNegatives}/{quality.localFalseNegatives}</strong> missed
              attacks caught by escalation &mdash; confident misses stay invisible to it
            </li>
            <li>
              <strong>{Math.round(quality.bundleBytesMean)} bytes</strong> sent per escalation,{" "}
              <strong>0 raw CAN bytes</strong> (allow-list: {quality.bundleFields.join(", ")})
            </li>
          </ul>
        </div>
      )}
    </section>
  );
}
