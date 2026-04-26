import { useState } from "react";

export default function AIAnalysis({ threat }) {
  const [result,   setResult]   = useState(null);
  const [loading,  setLoading]  = useState(false);
  const [history,  setHistory]  = useState([]);
  const [custom,   setCustom]   = useState("");

  const analyze = async (t, question = null) => {
    if (!t && !question) return;
    setLoading(true); setResult(null);

    const prompt = question
      ? `You are a senior cybersecurity analyst. Answer this follow-up question about the security incident:\n\nIncident: ${t?.type || "Unknown"} from ${t?.src || "unknown"}\nQuestion: ${question}\n\nBe direct, technical, and concise (under 150 words).`
      : `You are a senior cybersecurity analyst. Analyze this live threat detection event:

Threat Type: ${t.type}
Severity: ${t.severity.toUpperCase()}
Source IP: ${t.src}
Target System: ${t.target}
Engine Status: ${t.status}
Detection Time: ${t.time}

Provide:
1. **Attack Vector** — how the attack works (2 sentences)
2. **Potential Impact** — what could happen (2 sentences)
3. **Remediation Steps** — exactly 3 actionable bullet points
4. **Confidence Score** — X/100 with brief reasoning

Keep total response under 220 words. Be precise and technical.`;

    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          messages: [{ role: "user", content: prompt }],
        }),
      });
      const data = await res.json();
      const text = data.content?.find(b => b.type === "text")?.text || "Analysis unavailable.";
      const entry = { threat: t, question, text, ts: new Date().toLocaleTimeString("en-GB", { hour12: false }) };
      setResult(text);
      setHistory(p => [entry, ...p].slice(0, 10));
    } catch {
      setResult("⚠ API connection failed. Ensure VITE_ANTHROPIC_API_KEY is set.");
    } finally {
      setLoading(false);
    }
  };

  const ask = () => {
    if (!custom.trim()) return;
    analyze(threat, custom);
    setCustom("");
  };

  return (
    <div>
      <div className="pane-head">
        <h2>AI Threat Analysis</h2>
        <span className="pill info">Claude Sonnet</span>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 300px",gap:16}}>
        <div>
          {/* Selected threat */}
          {!threat && (
            <div className="card card-inner" style={{marginBottom:16,textAlign:"center",padding:"40px 20px"}}>
              <div style={{fontSize:32,marginBottom:12,opacity:0.3}}>◇</div>
              <div style={{fontFamily:"var(--font-mono)",fontSize:13,color:"var(--text-dim)"}}>
                No threat selected.<br/>Go to Live Monitor and click an event row.
              </div>
            </div>
          )}

          {threat && (
            <div className="card" style={{marginBottom:16}}>
              <div style={{padding:"10px 16px",borderBottom:"1px solid var(--border)",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <span className={`sev ${threat.severity}`}>{threat.severity}</span>
                  <span style={{fontFamily:"var(--font-mono)",fontSize:13,fontWeight:500,color:"var(--text-primary)"}}>{threat.type}</span>
                  <span style={{fontSize:12,color:"var(--text-dim)"}}>{threat.src} → {threat.target}</span>
                </div>
                <button className="btn primary" onClick={()=>analyze(threat)} disabled={loading}>
                  {loading ? "Analyzing..." : "Analyze with AI ↗"}
                </button>
              </div>
              <div style={{padding:"16px"}}>
                {loading && (
                  <div style={{display:"flex",alignItems:"center",gap:12}}>
                    <div className="thinking-dots">
                      <span/><span/><span/>
                    </div>
                    <span style={{fontSize:13,color:"var(--text-dim)",fontFamily:"var(--font-mono)"}}>Claude is analyzing the threat...</span>
                  </div>
                )}
                {result && !loading && (
                  <div className="ai-response">{result}</div>
                )}
                {!result && !loading && (
                  <div style={{fontSize:13,color:"var(--text-dim)"}}>Click "Analyze with AI" to get a full threat report.</div>
                )}
              </div>
            </div>
          )}

          {/* Follow-up Q */}
          {threat && (
            <div className="card card-inner">
              <div style={{fontFamily:"var(--font-mono)",fontSize:11,letterSpacing:"0.08em",textTransform:"uppercase",color:"var(--text-dim)",marginBottom:10}}>Follow-up Question</div>
              <div style={{display:"flex",gap:8}}>
                <input value={custom} onChange={e=>setCustom(e.target.value)}
                  onKeyDown={e=>e.key==="Enter"&&ask()}
                  placeholder="e.g. What CVE is associated with this attack?" />
                <button className="btn primary" onClick={ask} disabled={loading||!custom.trim()}>Ask ↗</button>
              </div>
            </div>
          )}
        </div>

        {/* History */}
        <div>
          <div style={{fontFamily:"var(--font-mono)",fontSize:11,letterSpacing:"0.08em",textTransform:"uppercase",color:"var(--text-dim)",marginBottom:10}}>Analysis History</div>
          {!history.length && <div style={{fontSize:12,color:"var(--text-dim)"}}>No analyses yet.</div>}
          {history.map((h,i)=>(
            <div key={i} className="card card-inner" style={{marginBottom:8,cursor:"pointer"}} onClick={()=>setResult(h.text)}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                <span style={{fontFamily:"var(--font-mono)",fontSize:12,fontWeight:500,color:"var(--text-primary)"}}>{h.threat?.type}</span>
                <span style={{fontSize:11,color:"var(--text-dim)",fontFamily:"var(--font-mono)"}}>{h.ts}</span>
              </div>
              {h.question
                ? <div style={{fontSize:11,color:"var(--blue)"}}>Q: {h.question.slice(0,40)}...</div>
                : <span className={`sev ${h.threat?.severity}`}>{h.threat?.severity}</span>
              }
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
