// Live animation of the team's own architecture doc (section 2).
//
// Only the ORDINARY DETECTION lane (Fleet replay -> Blue Team -> Simulated
// consumer) is animated live, because that's the lane that actually runs
// per window -- it's what the mock/real DefenderOutput stream represents.
// The adversarial testing/hardening lane (Red Team -> injector -> ground
// truth -> evidence gate) runs offline, once, comparing two frozen model
// versions on a held-out set -- it does not fire per window in the real
// system, so it's shown as a static reference strip underneath rather than
// animated in sync with live traffic. That's a deliberate accuracy choice:
// dramatizing it as live would show something that isn't how the pipeline
// actually works.

import { Fragment, useEffect, useRef, useState } from "react";
import { ACTIONS } from "./actionMeta";

const OFFLINE_LANE = [
  { id: "fleet2", label: "Fleet replay", sub: "Unchanged ROAD source" },
  { id: "red", label: "Red Team", sub: "Proposes attack spec" },
  { id: "blue2", label: "Blue Team", sub: "Scores altered window" },
  { id: "gt", label: "Ground truth check", sub: "Was it a missed attack?" },
  { id: "decision2", label: "Decision", sub: "Train vs. test split" },
  { id: "gate", label: "Evidence gate", sub: "Compare v1 vs v2" },
];

export default function ArchitectureDiagram({ output, attackAction }) {
  const isAttack = output?.decision === "ATTACK";
  const action = !output ? null : isAttack ? attackAction : "SIMULATED_FORWARD";
  const blueTone = !output ? "" : isAttack ? "node-critical" : "node-good";
  const consumerTone = action ? ACTIONS[action].nodeTone : "";

  // Pulse once on a genuine state change (ACCEPT <-> ATTACK), not on every
  // replay tick -- remounting per-tick made the whole lane strobe
  // continuously, especially at faster playback speeds. Nodes otherwise sit
  // calm and just hold their current color.
  const [pulseKey, setPulseKey] = useState(0);
  const prevDecisionRef = useRef(output?.decision);
  useEffect(() => {
    if (output && output.decision !== prevDecisionRef.current) {
      setPulseKey((k) => k + 1);
      prevDecisionRef.current = output.decision;
    }
  }, [output]);

  return (
    <section className="card arch-diagram">
      <div className="card-head">
        <h2>System architecture &mdash; live</h2>
        <span className="hint">Ordinary detection lane, flashes once when a window changes state</span>
      </div>

      <div className="arch-lane arch-lane-live" key={pulseKey}>
        <ArchNode label="Fleet replay" sub="Incoming traffic window" tone="node-pulse" />
        <ArchArrow />
        <ArchNode label="Blue Team" sub="One attack likelihood" tone={`node-pulse ${blueTone}`} />
        <ArchArrow />
        <ArchNode label="Simulated consumer" sub={action ? ACTIONS[action].label : "Waiting…"} tone={`node-pulse ${consumerTone}`} />
      </div>

      <div className="arch-offline-label">
        <span className="hint">Offline &middot; adversarial testing &amp; hardening (not live &mdash; runs once per model comparison)</span>
      </div>
      <div className="arch-lane arch-lane-offline">
        {OFFLINE_LANE.map((node, i) => (
          <Fragment key={node.id}>
            <ArchNode label={node.label} sub={node.sub} tone="node-dim" small />
            {i < OFFLINE_LANE.length - 1 && <ArchArrow dim />}
          </Fragment>
        ))}
      </div>
    </section>
  );
}

function ArchNode({ label, sub, tone = "", small = false }) {
  return (
    <div className={`arch-node ${tone} ${small ? "arch-node-small" : ""}`}>
      <div className="arch-node-label">{label}</div>
      <div className="arch-node-sub hint">{sub}</div>
    </div>
  );
}

function ArchArrow({ dim = false }) {
  return (
    <div className={`arch-arrow ${dim ? "arch-arrow-dim" : ""}`}>
      <span className="arch-dot" />
    </div>
  );
}
