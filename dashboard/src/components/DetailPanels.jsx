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

export function RoutingPanel() {
  return (
    <section className="card routing-panel">
      <div className="card-head">
        <h2>Local / cloud routing</h2>
      </div>
      <div className="routing-row">
        <span className="status-badge status-good">LOCAL &mdash; on-device</span>
        <span className="status-badge status-disabled" title="No cloud escalation path exists in the pipeline yet; this is an open team decision.">
          CLOUD &mdash; not wired up
        </span>
      </div>
      <p className="hint">
        Detection runs fully on-device. A cloud second opinion was scoped out of the
        core loop; showing it here as a placeholder pending the team's HP edge/cloud decision.
      </p>
    </section>
  );
}
