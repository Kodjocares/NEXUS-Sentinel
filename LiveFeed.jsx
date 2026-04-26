import { useState, useEffect, useRef } from "react";

const THREAT_TYPES = [
  { type: "Ransomware",        severity: "critical" },
  { type: "SQL Injection",     severity: "high"     },
  { type: "Port Scan",         severity: "medium"   },
  { type: "Brute Force",       severity: "high"     },
  { type: "XSS Attack",        severity: "medium"   },
  { type: "DDoS Probe",        severity: "critical" },
  { type: "Malware Dropper",   severity: "critical" },
  { type: "Phishing URL",      severity: "high"     },
  { type: "Keylogger",         severity: "critical" },
  { type: "Data Exfiltration", severity: "critical" },
  { type: "DNS Spoofing",      severity: "high"     },
  { type: "ARP Poisoning",     severity: "medium"   },
  { type: "Zero-day Exploit",  severity: "critical" },
  { type: "Lateral Movement",  severity: "high"     },
  { type: "Recon Sweep",       severity: "low"      },
];
const SOURCES  = ["185.234.219.14","91.108.4.201","103.72.48.99","45.153.160.2","194.165.16.11","77.83.197.3","31.14.252.17","198.199.77.93"];
const TARGETS  = ["/api/auth","/admin/login","DB:5432","/wp-admin","SSH:22","/api/users","RDP:3389","SMTP:25"];
const STATUS   = { critical:"BLOCKED", high:"QUARANTINED", medium:"FLAGGED", low:"LOGGED" };

let _id = 100;
function mkEvent() {
  const t = THREAT_TYPES[Math.floor(Math.random() * THREAT_TYPES.length)];
  return { id: _id++, ...t, src: SOURCES[Math.floor(Math.random()*SOURCES.length)], target: TARGETS[Math.floor(Math.random()*TARGETS.length)], time: new Date().toLocaleTimeString("en-GB",{hour12:false}), status: STATUS[t.severity], ts: Date.now() };
}

const SEV_C = { critical:"var(--red)", high:"var(--amber)", medium:"var(--blue)", low:"var(--green)" };

export default function LiveFeed({ onThreatSelect, selectedThreat, onStatsUpdate }) {
  const [events, setEvents] = useState(() => Array.from({length:10},mkEvent));
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("all");
  const [netData, setNetData] = useState(Array.from({length:24},()=>Math.floor(Math.random()*60+10)));
  const pausedRef = useRef(false);
  pausedRef.current = paused;

  useEffect(() => {
    const iv = setInterval(() => {
      if (pausedRef.current) return;
      const e = mkEvent();
      setEvents(p => [e, ...p].slice(0, 60));
      setNetData(p => [...p.slice(1), Math.floor(Math.random()*80+10)]);
      onStatsUpdate(s => ({
        ...s,
        blocked:     e.severity==="critical" ? s.blocked+1     : s.blocked,
        quarantined: e.severity==="high"     ? s.quarantined+1 : s.quarantined,
        flagged:     e.severity==="medium"   ? s.flagged+1     : s.flagged,
        scanned:     s.scanned + Math.floor(Math.random()*8+2),
      }));
    }, 2000);
    return () => clearInterval(iv);
  }, [onStatsUpdate]);

  const shown = filter === "all" ? events : events.filter(e => e.severity === filter);
  const sevCounts = ["critical","high","medium","low"].map(s => ({ s, n: events.filter(e=>e.severity===s).length }));
  const maxNet = Math.max(...netData,1);

  return (
    <div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 300px",gap:16}}>
        {/* Main feed */}
        <div className="card">
          <div style={{padding:"12px 16px",borderBottom:"1px solid var(--border)",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
            <div style={{display:"flex",alignItems:"center",gap:12}}>
              <span className="dot green" />
              <span style={{fontFamily:"var(--font-mono)",fontSize:12,fontWeight:500,letterSpacing:"0.08em",textTransform:"uppercase",color:"var(--text-primary)"}}>Threat Feed</span>
            </div>
            <div style={{display:"flex",gap:6,alignItems:"center"}}>
              {["all","critical","high","medium","low"].map(f=>(
                <button key={f} className="btn" style={{padding:"3px 10px",fontSize:11,borderColor:filter===f?"var(--teal)":"",color:filter===f?"var(--teal)":""}} onClick={()=>setFilter(f)}>{f}</button>
              ))}
              <button className={`btn ${paused?"primary":""}`} onClick={()=>setPaused(p=>!p)} style={{padding:"3px 10px",fontSize:11}}>{paused?"▶ Resume":"⏸ Pause"}</button>
            </div>
          </div>
          <div style={{maxHeight:400,overflowY:"auto"}}>
            <table className="data-table" style={{width:"100%"}}>
              <thead>
                <tr>
                  <th>Time</th><th>Threat</th><th>Source IP</th><th>Target</th><th>Severity</th><th>Status</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((ev,i)=>(
                  <tr key={ev.id} className={`${selectedThreat?.id===ev.id?"selected":""} ${i===0&&!paused?"new-row":""}`} onClick={()=>onThreatSelect(ev)}>
                    <td style={{color:"var(--text-dim)"}}>{ev.time}</td>
                    <td style={{color:"var(--text-primary)",fontWeight:500}}>{ev.type}</td>
                    <td>{ev.src}</td>
                    <td>{ev.target}</td>
                    <td><span className={`sev ${ev.severity}`}>{ev.severity}</span></td>
                    <td style={{color:"var(--text-dim)",fontSize:11}}>{ev.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right column */}
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          {/* Network sparkline */}
          <div className="card card-inner">
            <div style={{fontFamily:"var(--font-mono)",fontSize:11,letterSpacing:"0.08em",textTransform:"uppercase",color:"var(--text-dim)",marginBottom:10}}>Network Traffic</div>
            <div className="spark">
              {netData.map((v,i)=>(
                <div key={i} className="spark-bar" style={{height:`${(v/maxNet)*100}%`,background:i===netData.length-1?"var(--red)":"var(--teal)",opacity:0.6+(i/netData.length)*0.4}} />
              ))}
            </div>
            <div style={{display:"flex",justifyContent:"space-between",marginTop:6,fontSize:10,color:"var(--text-dim)",fontFamily:"var(--font-mono)"}}>
              <span>48s ago</span><span>now</span>
            </div>
          </div>

          {/* Severity bars */}
          <div className="card card-inner">
            <div style={{fontFamily:"var(--font-mono)",fontSize:11,letterSpacing:"0.08em",textTransform:"uppercase",color:"var(--text-dim)",marginBottom:12}}>Severity Breakdown</div>
            {sevCounts.map(({s,n})=>{
              const pct = Math.round((n/events.length)*100)||0;
              return (
                <div key={s} style={{marginBottom:10}}>
                  <div style={{display:"flex",justifyContent:"space-between",fontSize:11,marginBottom:4,fontFamily:"var(--font-mono)"}}>
                    <span style={{color:"var(--text-dim)",textTransform:"uppercase",letterSpacing:"0.06em"}}>{s}</span>
                    <span style={{color:SEV_C[s]}}>{n} ({pct}%)</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill" style={{width:`${pct}%`,background:SEV_C[s]}} />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected threat quick view */}
          {selectedThreat && (
            <div className="card card-inner" style={{borderColor:"var(--teal)"}}>
              <div style={{fontFamily:"var(--font-mono)",fontSize:11,letterSpacing:"0.08em",textTransform:"uppercase",color:"var(--teal)",marginBottom:10}}>Selected</div>
              <div style={{fontFamily:"var(--font-mono)",fontSize:13,fontWeight:500,color:"var(--text-primary)",marginBottom:4}}>{selectedThreat.type}</div>
              <div style={{fontSize:12,color:"var(--text-secondary)",marginBottom:2}}>From: {selectedThreat.src}</div>
              <div style={{fontSize:12,color:"var(--text-secondary)",marginBottom:10}}>Target: {selectedThreat.target}</div>
              <span className={`sev ${selectedThreat.severity}`}>{selectedThreat.severity}</span>
              <div style={{marginTop:10,fontSize:11,color:"var(--text-dim)"}}>→ Go to AI Reports for full analysis</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
