"use client";

import { useState } from "react";

const API = "http://127.0.0.1:8000/analyze";
const INKS = ["#2E7D6A", "#3B4C8A", "#B9821F", "#A63446", "#6B5B95", "#2F7F9E", "#7A8B3A", "#8A5A44"];
const EXAMPLES = [
  ["Legitimate", "https://example.com/products"],
  ["Typosquatting", "https://paypa1.com/login"],
  ["IP domain", "https://192.168.1.10/login"],
];

const tone = (v) => (v === "LIKELY_LEGITIMATE" ? "safe" : v === "SUSPICIOUS" ? "danger" : "warn");
const pretty = (v = "") => {
  const s = v.replaceAll("_", " ").toLowerCase();
  return s.charAt(0).toUpperCase() + s.slice(1);
};
const colorMap = (tokens = []) => {
  const m = {};
  tokens.forEach((t) => {
    if (!(t.type in m)) m[t.type] = INKS[Object.keys(m).length % INKS.length];
  });
  return m;
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeURL = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch(API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      setResult(await res.json());
    } catch {
      setResult({ verdict: "ERROR", explanation: "Could not reach the FormaLex backend at 127.0.0.1:8000. Start it and try again." });
    }
    setLoading(false);
  };

  return (
    <main className="page">
      <header className="masthead">
        <span className="wordmark">FormaLex</span>
        <span className="masthead-note">Phishing detection with automata and grammars</span>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <h1>Is this address a sentence in the language of safe URLs?</h1>
          <p className="lede">
            FormaLex breaks a URL into tokens, walks it through a finite automaton, then checks it against a
            context-free grammar of legitimate addresses and a set of phishing grammars.
          </p>
          <div className="addressbar">
            <input
              type="text"
              aria-label="URL to analyze"
              placeholder="https://paypa1.com/login"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && analyzeURL()}
              spellCheck={false}
            />
            <button onClick={analyzeURL} disabled={loading}>
              {loading ? "Analyzing" : "Analyze URL"}
            </button>
          </div>
          <div className="examples">
            <span>Try a sample:</span>
            {EXAMPLES.map(([label, u]) => (
              <button key={label} onClick={() => setUrl(u)}>{label}</button>
            ))}
          </div>
        </div>
        <HeroAutomaton />
      </section>

      <Pipeline stage={loading ? "run" : result ? "done" : "idle"} />

      {result && <Results r={result} />}

      <Theory />

      
    </main>
  );
}

/* ---------- layout helpers ---------- */

function Fig({ n, title, note, children, span }) {
  return (
    <figure className={`fig ${span ? "span" : ""}`}>
      <figcaption>
        <b>Figure {n}</b> {title}
      </figcaption>
      <div className="fig-body">{children}</div>
      {note && <p className="fig-note">{note}</p>}
    </figure>
  );
}

const Defs = () => (
  <defs>
    <marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0L10 5L0 10z" fill="#56676F" />
    </marker>
  </defs>
);

/* ---------- hero: simplified automaton with a token travelling it ---------- */

function HeroAutomaton() {
  const S = {
    q0: [60, 150], q1: [190, 70], q2: [190, 230], q3: [340, 70], qa: [468, 70], qr: [340, 230],
  };
  const r = 26;
  const E = ({ a, b, label, bad }) => {
    const [x1, y1] = S[a], [x2, y2] = S[b];
    const d = Math.hypot(x2 - x1, y2 - y1), ux = (x2 - x1) / d, uy = (y2 - y1) / d;
    const sx = x1 + ux * r, sy = y1 + uy * r, ex = x2 - ux * (r + 5), ey = y2 - uy * (r + 5);
    return (
      <g>
        <line x1={sx} y1={sy} x2={ex} y2={ey} className={bad ? "e bad" : "e"} markerEnd="url(#ah)" />
        <text x={(sx + ex) / 2} y={(sy + ey) / 2 - 9} textAnchor="middle" className="elabel">{label}</text>
      </g>
    );
  };
  return (
    <figure className="hero-fig" aria-label="Simplified automaton accepting well-formed URLs">
      <svg viewBox="0 0 540 300" role="img">
        <Defs />
        <line x1="8" y1="150" x2={60 - r - 4} y2="150" className="e" markerEnd="url(#ah)" />
        <E a="q0" b="q1" label="scheme" />
        <E a="q0" b="q2" label="raw IP" bad />
        <E a="q1" b="q3" label="domain" />
        <E a="q3" b="qa" label="path" />
        <E a="q2" b="qr" label="login" bad />
        {Object.entries(S).map(([k, [x, y]]) => (
          <g key={k} className={k === "qa" ? "st ok" : k === "qr" ? "st no" : "st"}>
            <circle cx={x} cy={y} r={r} />
            {k === "qa" && <circle cx={x} cy={y} r={r - 5} />}
            <text x={x} y={y + 4} textAnchor="middle">{k === "qa" ? "accept" : k === "qr" ? "trap" : k}</text>
          </g>
        ))}
        <circle r="6" className="traveller" />
      </svg>
      <figcaption>A simplified DFA. Safe addresses reach the accepting state; suspicious ones fall into a trap.</figcaption>
    </figure>
  );
}

/* ---------- pipeline ---------- */

function Pipeline({ stage }) {
  const steps = [
    ["URL", "raw string"], ["Lexer", "splits into tokens"], ["DFA", "tracks states"],
    ["CFG parser", "builds parse tree"], ["Verdict", "rule and grammar match"],
  ];
  return (
    <ol className={`pipeline ${stage}`} aria-label="Analysis pipeline">
      {steps.map(([a, b], i) => (
        <li key={a} style={{ "--i": i }}>
          <span className="dot" />
          <strong>{a}</strong>
          <em>{b}</em>
        </li>
      ))}
    </ol>
  );
}

/* ---------- results ---------- */

function Results({ r }) {
  const colors = colorMap(r.tokens);
  const t = tone(r.verdict);
  const matches = r.phishing_grammar_matches || [];
  const hasAnalysis = r.tokens || r.state_path || r.parse_tree;
  return (
    <section className="results">
      <div className={`verdict ${t}`}>
        <div>
          <h2>{pretty(r.verdict)}</h2>
          {r.attack_type && <p className="attack">Attack type: <b>{pretty(r.attack_type)}</b></p>}
        </div>
        <div className="verdict-text">
          <p>{r.explanation}</p>
          {r.rule && <p className="rule">Matched rule <code>{r.rule}</code></p>}
        </div>
      </div>

      {hasAnalysis && (
        <div className="figs">
          <Fig n={1} span title="Anatomy of the URL" note="Each segment is one token. Width follows the token's length in characters.">
            <UrlAnatomy tokens={r.tokens} colors={colors} />
          </Fig>
          <Fig n={2} span title="Path through the DFA" note="Arrows are numbered in the order the automaton took them. The outlined state is where it stopped.">
            <DfaPath path={r.state_path} tone={t} />
          </Fig>
          <Fig n={3} title="Grammar membership">
            <Venn accepted={!!r.grammar_membership} count={matches.length} tone={t} />
            <div className="chips">
              {matches.length ? matches.map((m, i) => <span key={i}>{m.type}</span>) : <small>No phishing grammar matched.</small>}
            </div>
          </Fig>
          <Fig n={4} title="Token mix">
            <Donut tokens={r.tokens} colors={colors} />
          </Fig>
          <Fig n={5} span title="CFG parse tree" note="Rounded boxes are non-terminals. Filled boxes are the terminals read from the URL.">
            <ParseTree root={r.parse_tree} />
          </Fig>
        </div>
      )}
    </section>
  );
}

function UrlAnatomy({ tokens, colors }) {
  if (!tokens?.length) return <p className="muted">No tokens returned.</p>;
  return (
    <div className="anatomy">
      {tokens.map((t, i) => (
        <div key={i} className="seg" style={{ flexGrow: Math.max(String(t.value).length, 3), "--c": colors[t.type] }}>
          <code>{t.value}</code>
          <span>{t.type}</span>
        </div>
      ))}
    </div>
  );
}

function DfaPath({ path = [], tone }) {
  if (!path.length) return <p className="muted">No state path returned.</p>;
  const names = [...new Set(path)];
  const pw = Math.max(46, ...names.map((n) => String(n).length * 7.4 + 22));
  const gap = pw + 64, H = 230, cy = 120, ph = 34;
  const cx = (s) => 50 + pw / 2 + names.indexOf(s) * gap;
  const W = 100 + pw + (names.length - 1) * gap;
  const last = path[path.length - 1];
  return (
    <div className="scroll">
      <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label="DFA state path">
        <Defs />
        <line x1="8" y1={cy} x2={cx(path[0]) - pw / 2 - 3} y2={cy} className="e" markerEnd="url(#ah)" />
        {path.slice(1).map((b, k) => {
          const a = path[k], xa = cx(a), xb = cx(b), n = k + 1;
          let d, lx, ly;
          if (a === b) {
            d = `M${xa - 12} ${cy - ph / 2} C${xa - 34} ${cy - 76} ${xa + 34} ${cy - 76} ${xa + 12} ${cy - ph / 2 - 3}`;
            lx = xa; ly = cy - 66;
          } else if (xb > xa && xb - xa === gap) {
            d = `M${xa + pw / 2} ${cy} L${xb - pw / 2 - 4} ${cy}`;
            lx = (xa + xb) / 2; ly = cy - 8;
          } else if (xb > xa) {
            const h = 26 + (xb - xa) * 0.18;
            d = `M${xa} ${cy - ph / 2} Q${(xa + xb) / 2} ${cy - ph / 2 - 2 * h} ${xb} ${cy - ph / 2 - 4}`;
            lx = (xa + xb) / 2; ly = cy - ph / 2 - h - 6;
          } else {
            const h = 26 + (xa - xb) * 0.18;
            d = `M${xa} ${cy + ph / 2} Q${(xa + xb) / 2} ${cy + ph / 2 + 2 * h} ${xb} ${cy + ph / 2 + 4}`;
            lx = (xa + xb) / 2; ly = cy + ph / 2 + h + 14;
          }
          return (
            <g key={k}>
              <path d={d} pathLength="1" className="e draw" style={{ animationDelay: `${k * 0.22}s` }} markerEnd="url(#ah)" />
              <text x={lx} y={ly} textAnchor="middle" className="step">{n}</text>
            </g>
          );
        })}
        {names.map((s) => (
          <g key={s} className={`pill ${s === last ? tone : ""}`}>
            {s === last && <rect x={cx(s) - pw / 2 - 4} y={cy - ph / 2 - 4} width={pw + 8} height={ph + 8} rx="11" className="outer" />}
            <rect x={cx(s) - pw / 2} y={cy - ph / 2} width={pw} height={ph} rx="8" />
            <text x={cx(s)} y={cy + 4} textAnchor="middle">{s}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}

function Venn({ accepted, count, tone }) {
  const both = accepted && count > 0;
  const p = both ? [200, 125] : accepted ? [108, 125] : count > 0 ? [292, 125] : [200, 236];
  return (
    <svg viewBox="0 0 400 256" className="venn" role="img" aria-label="Venn diagram of grammar membership">
      <circle cx="150" cy="125" r="80" className="vl" />
      <circle cx="250" cy="125" r="80" className="vr" />
      <text x="100" y="24" textAnchor="middle" className="vt">Legitimate CFG</text>
      <text x="300" y="24" textAnchor="middle" className="vt">Phishing grammars</text>
      <circle cx={p[0]} cy={p[1]} r="8" className={`vdot ${tone}`} />
      <text x={p[0]} y={p[1] + 26} textAnchor="middle" className="vt strong">this URL</text>
    </svg>
  );
}

function Donut({ tokens = [], colors }) {
  if (!tokens.length) return <p className="muted">No tokens returned.</p>;
  const counts = {};
  tokens.forEach((t) => (counts[t.type] = (counts[t.type] || 0) + 1));
  const C = 2 * Math.PI * 52;
  let acc = 0;
  return (
    <div className="donut">
      <svg viewBox="0 0 140 140" role="img" aria-label="Token types">
        <g transform="rotate(-90 70 70)">
          {Object.entries(counts).map(([k, n]) => {
            const len = (n / tokens.length) * C, off = -acc;
            acc += len;
            return <circle key={k} cx="70" cy="70" r="52" fill="none" stroke={colors[k]} strokeWidth="18"
              strokeDasharray={`${Math.max(len - 2, 0)} ${C}`} strokeDashoffset={off} />;
          })}
        </g>
        <text x="70" y="68" textAnchor="middle" className="dn">{tokens.length}</text>
        <text x="70" y="84" textAnchor="middle" className="dl">tokens</text>
      </svg>
      <ul>
        {Object.entries(counts).map(([k, n]) => (
          <li key={k}><i style={{ background: colors[k] }} />{k}<b>{n}</b></li>
        ))}
      </ul>
    </div>
  );
}

function ParseTree({ root }) {
  if (!root) return <p className="muted">No parse tree available.</p>;
  let leaf = 0;
  const nodes = [], edges = [];
  const walk = (n, d) => {
    const kids = (n.children || []).map((c) => walk(c, d + 1));
    const x = kids.length ? (kids[0].x + kids[kids.length - 1].x) / 2 : leaf++;
    const me = { n, x, d, term: !kids.length };
    nodes.push(me);
    kids.forEach((k) => edges.push([me, k]));
    return me;
  };
  walk(root, 0);
  const w = (s) => Math.max(46, String(s).length * 7.6 + 20);
  const gx = Math.max(...nodes.map((o) => w(o.n.symbol))) + 18, gy = 66;
  const depth = Math.max(...nodes.map((o) => o.d));
  const X = (o) => 30 + gx / 2 + o.x * gx, Y = (o) => 30 + o.d * gy;
  const W = 60 + Math.max(leaf, 1) * gx, H = 60 + depth * gy;
  return (
    <div className="scroll">
      <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label="CFG parse tree">
        {edges.map(([a, b], i) => (
          <path key={i} d={`M${X(a)} ${Y(a) + 14} C${X(a)} ${Y(a) + 40} ${X(b)} ${Y(b) - 40} ${X(b)} ${Y(b) - 14}`} className="te" />
        ))}
        {nodes.map((o, i) => (
          <g key={i} className={o.term ? "tn term" : "tn"}>
            <rect x={X(o) - w(o.n.symbol) / 2} y={Y(o) - 14} width={w(o.n.symbol)} height="28" rx={o.term ? 4 : 14} />
            <text x={X(o)} y={Y(o) + 4} textAnchor="middle">{o.n.symbol}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}

/* ---------- theory: where each tool sits in the Chomsky hierarchy ---------- */

function Theory() {
  return (
    <section className="theory">
      <div>
        <h2>Why two machines?</h2>
        <p>
          The shape of a URL, such as which characters may appear and where, is a regular language, so a finite
          automaton can check it in one pass. Structure that nests, such as subdomains inside domains inside hosts, needs
          a context-free grammar and a parse tree. FormaLex uses each where it fits.
        </p>
      </div>
      <Fig n="A" title="The two languages FormaLex works with">
        <svg viewBox="0 0 420 270" className="chomsky" role="img" aria-label="Regular languages nested inside context-free languages">
          <ellipse cx="210" cy="140" rx="200" ry="122" className="c0" />
          <ellipse cx="210" cy="156" rx="146" ry="84" className="c1" />
          <ellipse cx="210" cy="176" rx="84" ry="44" className="c2" />
          <text x="210" y="38" textAnchor="middle">All languages</text>
          <text x="210" y="102" textAnchor="middle" className="b">Context-free</text>
          <text x="210" y="118" textAnchor="middle" className="s">CFG and parse tree</text>
          <text x="210" y="172" textAnchor="middle" className="b">Regular</text>
          <text x="210" y="188" textAnchor="middle" className="s">DFA and lexer</text>
        </svg>
      </Fig>
    </section>
  );
}