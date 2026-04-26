import { useState, useRef, useEffect } from "react";
import LiveFeed from "./components/LiveFeed";
import FileScanner from "./components/FileScanner";
import YaraPanel from "./components/YaraPanel";
import AIAnalysis from "./components/AIAnalysis";
import NetworkGraph from "./components/NetworkGraph";
import "./App.css";

const NAV = [
  { id: "monitor", label: "Live Monitor", icon: "◉" },
  { id: "scanner", label: "File Scanner", icon: "⬡" },
  { id: "yara",    label: "YARA Rules",   icon: "◈" },
  { id: "forensix",label: "PyForensix",   icon: "⬟" },
  { id: "reports", label: "AI Reports",   icon: "◇" },
];

export default function App() {
  const [tab, setTab] = useState("monitor");
  const [stats, setStats] = useState({ blocked: 247, quarantined: 89, flagged: 312, scanned: 14802 });
  const [selectedThreat, setSelectedThreat] = useState(null);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-hex">⬡</span>
          <div>
            <div className="brand-name">NEXUS</div>
            <div className="brand-sub">SENTINEL v2.0</div>
          </div>
        </div>

        <nav>
          {NAV.map(n => (
            <button key={n.id} className={`nav-btn ${tab === n.id ? "active" : ""}`} onClick={() => setTab(n.id)}>
              <span className="nav-icon">{n.icon}</span>
              <span>{n.label}</span>
              {n.id === "monitor" && <span className="pill live">LIVE</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          <span className="dot green" />
          <span>Engine Online</span>
        </div>
      </aside>

      <div className="body">
        {/* Top status bar */}
        <header className="topbar">
          {[
            { k: "Threats Blocked", v: stats.blocked, c: "red" },
            { k: "Quarantined", v: stats.quarantined, c: "amber" },
            { k: "Flagged", v: stats.flagged, c: "blue" },
            { k: "Files Scanned", v: stats.scanned.toLocaleString(), c: "green" },
          ].map(s => (
            <div key={s.k} className={`stat-card ${s.c}`}>
              <div className="stat-label">{s.k}</div>
              <div className="stat-val">{s.v}</div>
            </div>
          ))}
        </header>

        <main className="main">
          {tab === "monitor"  && <LiveFeed onThreatSelect={setSelectedThreat} selectedThreat={selectedThreat} onStatsUpdate={setStats} />}
          {tab === "scanner"  && <FileScanner />}
          {tab === "yara"     && <YaraPanel />}
          {tab === "forensix" && <ForensixPanel />}
          {tab === "reports"  && <AIAnalysis threat={selectedThreat} />}
        </main>
      </div>
    </div>
  );
}

function ForensixPanel() {
  const [log, setLog] = useState([
    "PyForensix v3.0 — ready.",
    "YARA engine loaded: 47 rules active.",
    "Packet capture: eth0 | Scapy backend initialized.",
    "Feeds: AbuseIPDB ✓  VirusTotal ✓  MalwareBazaar ✓",
    "> Awaiting command...",
  ]);
  const [cmd, setCmd] = useState("");
  const end = useRef(null);

  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth" }); }, [log]);

  const run = () => {
    if (!cmd.trim()) return;
    setLog(p => [...p, `$ ${cmd}`, "→ Dispatched to backend at http://localhost:5000/api/forensix"]);
    setCmd("");
  };

  return (
    <div className="forensix">
      <div className="pane-head">
        <h2>PyForensix Terminal</h2>
        <span className="pill info">localhost:5000</span>
      </div>
      <div className="terminal">
        {log.map((l, i) => <div key={i} className={`tline ${l.startsWith("$") ? "tcmd" : l.startsWith(">") ? "tprompt" : ""}`}>{l}</div>)}
        <div ref={end} />
      </div>
      <div className="term-row">
        <span className="tpfx">$</span>
        <input className="tinput" value={cmd} onChange={e => setCmd(e.target.value)}
          onKeyDown={e => e.key === "Enter" && run()}
          placeholder="python pyforensix.py --scan /path/to/target --yara rules/" />
        <button className="tbtn" onClick={run}>RUN ↗</button>
      </div>
    </div>
  );
}
