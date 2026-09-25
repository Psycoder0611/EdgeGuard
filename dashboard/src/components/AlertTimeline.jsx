import { useState } from "react";
import { parseEvidence } from "../utils/parseEvidence";
import { formatLatency } from "../utils/latency";

const MAX_VISIBLE = 60;

export default function AlertTimeline({ history, onSeek }) {
  const [hoverIdx, setHoverIdx] = useState(null);
  const visible = history.slice(-MAX_VISIBLE);
  const offset = history.length - visible.length;

  return (
    <section className="card alert-timeline">
      <div className="card-head">
        <h2>Alert timeline</h2>
        <span className="legend">
          <span className="legend-dot legend-dot-good" /> Accept
          <span className="legend-dot legend-dot-critical" /> Attack
          <span className="hint">&nbsp;&middot; click a bar to jump</span>
        </span>
      </div>

      <div className="timeline-strip">
        {visible.map((output, i) => {
          const globalIdx = offset + i;
          const isAttack = output.decision === "ATTACK";
          return (
            <div
              key={output.window_id}
              className={`timeline-mark ${isAttack ? "timeline-mark-critical" : "timeline-mark-good"} ${globalIdx === history.length - 1 ? "timeline-mark-now" : ""}`}
              onClick={() => onSeek?.(globalIdx)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onSeek?.(globalIdx); }}
              role="button"
              aria-label={`Jump to ${output.window_id}`}
              onMouseEnter={() => setHoverIdx(globalIdx)}
              onMouseLeave={() => setHoverIdx((cur) => (cur === globalIdx ? null : cur))}
              tabIndex={0}
              onFocus={() => setHoverIdx(globalIdx)}
              onBlur={() => setHoverIdx((cur) => (cur === globalIdx ? null : cur))}
            />
          );
        })}
      </div>

      {hoverIdx !== null && history[hoverIdx] && (
        <TimelineTooltip output={history[hoverIdx]} />
      )}
    </section>
  );
}

function TimelineTooltip({ output }) {
  const { stage, canId } = parseEvidence(output.evidence);
  const latency = formatLatency(output.latency_ms);
  return (
    <div className="timeline-tooltip">
      <div className="mono">{output.window_id}</div>
      <div>
        score <span className="mono">{output.attack_score.toFixed(3)}</span>
        {" · "}
        {output.decision}
        {stage && <> {" · "}{stage}</>}
        {canId && <> {" · "}CAN {canId}</>}
        {latency && <> {" · "}decided in <span className="mono">{latency}</span></>}
      </div>
      <div className="hint">{output.evidence}</div>
    </div>
  );
}
