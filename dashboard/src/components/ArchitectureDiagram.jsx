// EdgeGuard architecture, drawn as a glowing "circuit board".
//
// Live lane (top): traffic window -> Defender -> simulated consumer. Glowing
// packets travel along the traces; each box lights up with a ripple the
// moment a packet reaches it. Colors follow the current replayed window:
// an attack turns the incoming packets red and the Defender's shield red.
//
// Offline lane (bottom): the adversarial testing & hardening loop
// (ROAD source -> Attacker -> Defender -> ground truth -> train/test ->
// evidence gate), with an amber feedback trace from the evidence gate back
// up to the live Defender (the gate decides which model version is used).
// In the real system this lane runs once per model comparison, not per
// window, so it loops here as an illustration and is labeled offline.
//
// All motion is SVG SMIL (animateMotion / animate), timed so both lanes
// share one step length: a packet always arrives exactly when the next box
// lights up.

const STEP = 2; // seconds per box, both lanes (slow and readable)
const START = 1.2; // wait for the entrance pop-in before the loop starts

const C = {
  cyan: "#22d3ee",
  blue: "#3b82f6",
  red: "#f04452",
  amber: "#fbbf24",
  green: "#22c55e",
  violet: "#a78bfa",
  pink: "#e879f9",
};

const ACTION_STYLE = {
  SIMULATED_FORWARD: { color: C.green, icon: "forward", label: "Forwarded" },
  SIMULATED_ALERT: { color: C.amber, icon: "bell", label: "Alert raised" },
  SIMULATED_ISOLATION: { color: C.red, icon: "lock", label: "Isolated" },
};

const LIVE_Y = 130;
const OFF_Y = 380;
const LIVE_W = 250;
const LIVE_H = 88;
const OFF_W = 156;
const OFF_H = 72;
const LIVE_X = [185, 600, 1015];
const OFF_X = [98, 299, 500, 701, 902, 1103];

export default function ArchitectureDiagram({ output, attackAction }) {
  const isAttack = output?.decision === "ATTACK";
  const action = !output ? "SIMULATED_FORWARD" : isAttack ? attackAction : "SIMULATED_FORWARD";
  const act = ACTION_STYLE[action];

  const live = [
    { label: "Traffic window", color: isAttack ? C.red : C.cyan, icon: "wave" },
    { label: "Defender", color: C.blue, icon: "shield", alarm: isAttack },
    { label: act.label, color: act.color, icon: act.icon },
  ];
  const offline = [
    { label: "ROAD source", color: C.cyan, icon: "db" },
    { label: "Attacker", color: C.red, icon: "target" },
    { label: "Defender", color: C.blue, icon: "shield" },
    { label: "Missed attack?", color: C.violet, icon: "check" },
    { label: "Train vs. test", color: C.pink, icon: "split" },
    { label: "v1 vs v2", color: C.amber, icon: "gate" },
  ];

  const liveT = STEP * live.length;
  const offT = STEP * offline.length;

  const liveTraces = [0, 1].map((i) => ({
    id: `eg-live-${i}`,
    d: `M ${LIVE_X[i] + LIVE_W / 2} ${LIVE_Y} L ${LIVE_X[i + 1] - LIVE_W / 2} ${LIVE_Y}`,
    color: i === 0 ? live[0].color : act.color,
  }));
  const offTraces = [0, 1, 2, 3, 4].map((i) => ({
    id: `eg-off-${i}`,
    d: `M ${OFF_X[i] + OFF_W / 2} ${OFF_Y} L ${OFF_X[i + 1] - OFF_W / 2} ${OFF_Y}`,
    color: offline[i].color,
  }));
  // Drawn defender -> gate so the label reads left-to-right; the packet
  // rides it in reverse (gate -> defender).
  const loopD = `M ${LIVE_X[1] + 30} ${LIVE_Y + LIVE_H / 2} C 640 262, ${OFF_X[5]} 250, ${OFF_X[5]} ${OFF_Y - OFF_H / 2}`;

  return (
    <section className="card arch-diagram">
      <div className="card-head">
        <h2>System architecture</h2>
        <span className={`status-badge ${isAttack ? "status-critical" : "status-good"}`}>
          {isAttack ? "Attack blocked" : "Traffic clean"}
        </span>
      </div>

      <div className="arch-board">
        <svg viewBox="0 0 1200 470" className="arch-svg" role="img"
             aria-label="EdgeGuard architecture: live detection lane and offline hardening loop">
          <defs>
            <pattern id="eg-grid" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="1" cy="1" r="1" fill="rgba(148,163,184,0.13)" />
            </pattern>
            <linearGradient id="eg-scan" x1="0" x2="1">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0" />
              <stop offset="50%" stopColor="#22d3ee" stopOpacity="0.10" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
            </linearGradient>
            <filter id="eg-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="eg-soft" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="14" />
            </filter>
            {[...liveTraces, ...offTraces].map((t) => <path key={t.id} id={t.id} d={t.d} />)}
            <path id="eg-loop" d={loopD} />
          </defs>

          <rect width="1200" height="470" fill="url(#eg-grid)" />
          <rect y="0" width="220" height="470" fill="url(#eg-scan)">
            <animate attributeName="x" values="-240;1220" dur="7s" repeatCount="indefinite" />
          </rect>

          <text x="24" y="44" className="arch-lane-title" fill={C.cyan}>LIVE DETECTION</text>
          <text x="24" y="300" className="arch-lane-title" fill={C.violet}>OFFLINE · HARDENING LOOP</text>

          {/* feedback: evidence gate promotes the model the live Defender runs */}
          <Trace d={loopD} color={C.amber} dashed />
          <text className="arch-loop-label" fill={C.amber}>
            <textPath href="#eg-loop" startOffset="38%">◂ promotes model</textPath>
          </text>
          <Packets href="#eg-loop" color={C.amber} T={offT} begin={START + 5.25 * STEP} travel={0.7 * STEP} reverse />

          {liveTraces.map((t, i) => (
            <g key={t.id}>
              <Trace d={t.d} color={t.color} />
              <Packets href={`#${t.id}`} color={t.color} T={liveT} begin={START + (i + 0.3) * STEP} travel={0.7 * STEP} />
            </g>
          ))}
          {offTraces.map((t, i) => (
            <g key={t.id}>
              <Trace d={t.d} color={t.color} />
              <Packets href={`#${t.id}`} color={t.color} T={offT} begin={START + (i + 0.3) * STEP} travel={0.7 * STEP} />
            </g>
          ))}

          {live.map((n, i) => (
            <Node key={`l${i}`} {...n} x={LIVE_X[i]} y={LIVE_Y} w={LIVE_W} h={LIVE_H}
                  step={i + 1} T={liveT} begin={START + i * STEP} enter={i * 0.25} big />
          ))}
          {offline.map((n, i) => (
            <Node key={`o${i}`} {...n} x={OFF_X[i]} y={OFF_Y} w={OFF_W} h={OFF_H}
                  step={i + 1} T={offT} begin={START + i * STEP} enter={0.75 + i * 0.15} />
          ))}
        </svg>
      </div>
    </section>
  );
}

function Trace({ d, color, dashed = false }) {
  return (
    <g>
      <path d={d} stroke={color} strokeOpacity="0.22" strokeWidth="6" fill="none" strokeLinecap="round" />
      <path d={d} stroke={color} strokeOpacity="0.75" strokeWidth="1.6" fill="none"
            strokeDasharray={dashed ? "6 7" : "2 9"} strokeLinecap="round" className="arch-trace-flow" />
    </g>
  );
}

// A glowing comet: head + two fading tail dots, riding the trace once per cycle.
function Packets({ href, color, T, begin, travel, reverse = false }) {
  const f = +(travel / T).toFixed(4);
  return [0, 0.07, 0.14].map((lag, k) => (
    <circle key={k} r={[6, 4, 2.6][k]} fill={color} opacity="0" filter="url(#eg-glow)">
      <animateMotion dur={`${T}s`} begin={`${begin + lag}s`} repeatCount="indefinite"
                     keyPoints={reverse ? "1;0;0" : "0;1;1"} keyTimes={`0;${f};1`} calcMode="linear">
        <mpath href={href} />
      </animateMotion>
      <animate attributeName="opacity" dur={`${T}s`} begin={`${begin + lag}s`} repeatCount="indefinite"
               values={`0;${1 - k * 0.3};${1 - k * 0.3};0;0`} keyTimes={`0;0.005;${(f - 0.01).toFixed(4)};${f};1`} />
    </circle>
  ));
}

function Node({ label, color, icon, x, y, w, h, step, T, begin, enter, big = false, alarm = false }) {
  const n = T / STEP; // boxes in this lane
  const a = (0.04 / (n / 3)).toFixed(4); // quick rise
  const b = (0.6 / n).toFixed(4); // highlight lasts ~60% of one step
  const iconX = -w / 2 + (big ? 42 : 28);
  const textX = -w / 2 + (big ? 76 : 50);

  return (
    <g transform={`translate(${x} ${y})`}>
      <g className="arch-enter" style={{ animationDelay: `${enter}s` }}>
        {/* soft aura, flares when a packet arrives */}
        <rect x={-w / 2} y={-h / 2} width={w} height={h} rx="16" fill={color} opacity="0.08" filter="url(#eg-soft)">
          <animate attributeName="opacity" values="0.08;0.75;0.08;0.08" keyTimes={`0;${a};${b};1`}
                   dur={`${T}s`} begin={`${begin}s`} repeatCount="indefinite" />
        </rect>

        {/* ripple ring */}
        <rect x={-w / 2} y={-h / 2} width={w} height={h} rx="16" fill="none" stroke={color} strokeWidth="2" opacity="0">
          <animateTransform attributeName="transform" type="scale" values="1;1.16;1.16" keyTimes={`0;${b};1`}
                            dur={`${T}s`} begin={`${begin}s`} repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.9;0;0" keyTimes={`0;${b};1`}
                   dur={`${T}s`} begin={`${begin}s`} repeatCount="indefinite" />
        </rect>

        <g>
          <animateTransform attributeName="transform" type="scale" values="1;1.07;1;1"
                            keyTimes={`0;${a};${(2 * a).toFixed(4)};1`} dur={`${T}s`} begin={`${begin}s`} repeatCount="indefinite" />
          <rect x={-w / 2} y={-h / 2} width={w} height={h} rx="16" fill="#0c1118" stroke={color} strokeWidth="1.6" />
          <rect x={-w / 2} y={-h / 2} width={w} height={h} rx="16" fill={color} opacity="0.1" />
          {/* bright edge that lights up with the box */}
          <rect x={-w / 2} y={-h / 2} width={w} height={h} rx="16" fill="none" stroke={color} strokeWidth="3"
                opacity="0" filter="url(#eg-glow)">
            <animate attributeName="opacity" values="0;1;0;0" keyTimes={`0;${a};${b};1`}
                     dur={`${T}s`} begin={`${begin}s`} repeatCount="indefinite" />
          </rect>

          <text x={w / 2 - 12} y={-h / 2 + 18} className="arch-step" textAnchor="end" fill={color}>
            {String(step).padStart(2, "0")}
          </text>

          <g transform={`translate(${iconX} 0)`}>
            {icon === "shield" && (
              <circle r={big ? 24 : 17} fill="none" stroke={alarm ? C.red : color} strokeWidth="1.4"
                      strokeDasharray="3 5" opacity="0.8">
                <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="6s" repeatCount="indefinite" />
              </circle>
            )}
            <circle r={big ? 18 : 13} fill={alarm ? C.red : color} opacity={alarm ? 0.3 : 0.18} />
            <Icon name={icon} color={alarm ? "#ff8a94" : color} s={big ? 1 : 0.75} />
          </g>

          <text x={textX} y={big ? 7 : 5} className={big ? "arch-label" : "arch-label arch-label-sm"} fill={color}>
            {label}
          </text>

          {alarm && (
            <rect x={-w / 2 - 5} y={-h / 2 - 5} width={w + 10} height={h + 10} rx="20" fill="none"
                  stroke={C.red} strokeWidth="2" className="arch-alarm" />
          )}
        </g>
      </g>
    </g>
  );
}

// Tiny line icons, 24x24 centered on 0,0.
function Icon({ name, color, s = 1 }) {
  const p = { fill: "none", stroke: color, strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round" };
  const paths = {
    wave: <path d="M-10 0 L-6 0 L-3 -7 L1 7 L4 -3 L6 0 L10 0" {...p} />,
    shield: <><path d="M0 -10 L8 -6.5 V0 C8 5 4.5 8.5 0 10 C-4.5 8.5 -8 5 -8 0 V-6.5 Z" {...p} /><path d="M-3.5 0 L-1 2.5 L4 -2.5" {...p} /></>,
    forward: <><path d="M-8 0 H7" {...p} /><path d="M2 -5 L7 0 L2 5" {...p} /></>,
    bell: <><path d="M-6 3 V-2 C-6 -6 -3 -8 0 -8 C3 -8 6 -6 6 -2 V3 L8 5 H-8 Z" {...p} /><path d="M-2 8 H2" {...p} /></>,
    lock: <><rect x="-7" y="-2" width="14" height="10" rx="2" {...p} /><path d="M-4 -2 V-5 C-4 -9 4 -9 4 -5 V-2" {...p} /></>,
    db: <><ellipse cx="0" cy="-6" rx="7" ry="3" {...p} /><path d="M-7 -6 V6 C-7 10 7 10 7 6 V-6" {...p} /><path d="M-7 0 C-7 4 7 4 7 0" {...p} /></>,
    target: <><circle r="8" {...p} /><circle r="3.5" {...p} /><path d="M0 -12 V-9 M0 9 V12 M-12 0 H-9 M9 0 H12" {...p} /></>,
    check: <><circle r="8.5" {...p} /><path d="M-4 0 L-1 3 L4.5 -3" {...p} /></>,
    split: <><path d="M-8 0 H-2 L4 -6 H8 M-2 0 L4 6 H8" {...p} /></>,
    gate: <><path d="M-8 8 V-5 M8 8 V-5 M-10 -5 H10" {...p} /><path d="M-4 -1 L0 3 L4 -1" {...p} /></>,
  };
  return <g transform={`scale(${s})`}>{paths[name]}</g>;
}
