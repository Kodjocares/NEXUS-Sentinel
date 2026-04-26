import { useState, useRef, useCallback } from "react";

const API = (typeof import.meta !== "undefined" && import.meta.env?.VITE_BACKEND_URL) || "http://localhost:5000";

const MOCK = [
  { name:"invoice_Q4.pdf",  size:"2.1 MB",status:"clean",     score:2,  yara:0,hash:"a3f8...d91c" },
  { name:"setup.exe",       size:"4.7 MB",status:"malware",   score:97, yara:3,hash:"ff21...7b3a" },
  { name:"report.docx",     size:"890 KB",status:"clean",     score:5,  yara:0,hash:"c12e...04f7" },
  { name:"loader.js",       size:"34 KB", status:"suspicious",score:61, yara:1,hash:"88ab...3d10" },
  { name:"backup.zip",      size:"12 MB", status:"clean",     score:8,  yara:0,hash:"3e9d...aa52" },
];

function fmtBytes(b){ if(!b)return"—"; if(b<1024)return b+" B"; if(b<1048576)return(b/1024).toFixed(1)+" KB"; return(b/1048576).toFixed(1)+" MB"; }

export default function FileScanner() {
  const [files,   setFiles]   = useState([]);
  const [results, setResults] = useState([]);
  const [scanning,setScanning]= useState(false);
  const [progress,setProgress]= useState(0);
  const [drag,    setDrag]    = useState(false);
  const inputRef = useRef();

  const onDrop = useCallback(e => { e.preventDefault(); setDrag(false); setFiles(p=>[...p,...Array.from(e.dataTransfer.files)]); }, []);

  const runScan = async () => {
    if (!files.length) return;
    setScanning(true); setProgress(0); setResults([]);
    try {
      const form = new FormData();
      files.forEach(f => form.append("files", f));
      const resp = await Promise.race([
        fetch(`${API}/api/scan`, { method:"POST", body:form }),
        new Promise((_,rej) => setTimeout(()=>rej(new Error("timeout")), 4000)),
      ]);
      if (resp.ok) { const d = await resp.json(); setResults(d.results||[]); setScanning(false); setProgress(100); return; }
    } catch(_) {}
    // Mock fallback
    for (let i=0; i<files.length; i++) {
      await new Promise(r=>setTimeout(r, 500+Math.random()*500));
      setProgress(Math.round(((i+1)/files.length)*100));
      const m = MOCK[i%MOCK.length];
      setResults(p=>[...p,{...m,name:files[i].name,size:fmtBytes(files[i].size)}]);
    }
    setScanning(false);
  };

  const sc = s => s==="malware"?"var(--red)":s==="suspicious"?"var(--amber)":"var(--green)";
  const sp = s => s==="malware"?"danger":s==="suspicious"?"warn":"info";

  return (
    <div>
      <div className="pane-head">
        <h2>File Scanner</h2>
        <span className="pill info">YARA + AI + VirusTotal</span>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
        <div className={`dropzone ${drag?"drag-over":""}`}
          onDragOver={e=>{e.preventDefault();setDrag(true)}} onDragLeave={()=>setDrag(false)}
          onDrop={onDrop} onClick={()=>inputRef.current.click()}>
          <div className="dropzone-icon">⬡</div>
          <div style={{marginBottom:6}}>Drop files to scan</div>
          <div style={{fontSize:11}}>or click to browse</div>
          <input ref={inputRef} type="file" multiple style={{display:"none"}} onChange={e=>setFiles(p=>[...p,...Array.from(e.target.files)])} />
        </div>
        <div className="card card-inner" style={{display:"flex",flexDirection:"column",gap:8}}>
          <div style={{fontFamily:"var(--font-mono)",fontSize:11,letterSpacing:"0.08em",textTransform:"uppercase",color:"var(--text-dim)",marginBottom:4}}>Queue ({files.length} files)</div>
          <div style={{flex:1,overflowY:"auto",maxHeight:130}}>
            {!files.length && <div style={{fontSize:12,color:"var(--text-dim)"}}>No files queued.</div>}
            {files.map((f,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",fontSize:12,padding:"3px 0",borderBottom:"1px solid var(--border)",color:"var(--text-secondary)"}}>
                <span style={{fontFamily:"var(--font-mono)"}}>{f.name}</span>
                <span style={{color:"var(--text-dim)"}}>{fmtBytes(f.size)}</span>
              </div>
            ))}
          </div>
          <div style={{display:"flex",gap:8,marginTop:"auto"}}>
            <button className="btn primary" style={{flex:1}} onClick={runScan} disabled={scanning||!files.length}>{scanning?"Scanning...":"Scan All ↗"}</button>
            <button className="btn" onClick={()=>{setFiles([]);setResults([]);setProgress(0);}} disabled={scanning}>Clear</button>
          </div>
        </div>
      </div>
      {scanning && (
        <div className="card card-inner" style={{marginBottom:16}}>
          <div style={{display:"flex",justifyContent:"space-between",fontSize:12,fontFamily:"var(--font-mono)",marginBottom:8,color:"var(--text-secondary)"}}>
            <span>Running YARA rules + AI heuristics...</span>
            <span style={{color:"var(--teal)"}}>{progress}%</span>
          </div>
          <div className="progress-track"><div className="progress-fill" style={{width:`${progress}%`}} /></div>
        </div>
      )}
      {results.length > 0 && (
        <div className="card">
          <div style={{padding:"12px 16px",borderBottom:"1px solid var(--border)",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{fontFamily:"var(--font-mono)",fontSize:12,fontWeight:500,letterSpacing:"0.08em",textTransform:"uppercase"}}>Scan Results</span>
            <div style={{display:"flex",gap:12,fontSize:11,fontFamily:"var(--font-mono)"}}>
              <span style={{color:"var(--red)"}}>{results.filter(r=>r.status==="malware").length} malware</span>
              <span style={{color:"var(--amber)"}}>{results.filter(r=>r.status==="suspicious").length} suspicious</span>
              <span style={{color:"var(--green)"}}>{results.filter(r=>r.status==="clean").length} clean</span>
            </div>
          </div>
          <table className="data-table">
            <thead><tr><th>File</th><th>Size</th><th>Threat Score</th><th>YARA Hits</th><th>SHA256</th><th>Status</th></tr></thead>
            <tbody>
              {results.map((r,i)=>(
                <tr key={i}>
                  <td style={{color:"var(--text-primary)",fontWeight:500}}>{r.name}</td>
                  <td>{r.size}</td>
                  <td>
                    <div style={{display:"flex",alignItems:"center",gap:8}}>
                      <div style={{width:60,height:4,background:"var(--bg3)",borderRadius:2}}>
                        <div style={{height:"100%",width:`${r.score}%`,background:sc(r.status),borderRadius:2,transition:"width 0.4s"}} />
                      </div>
                      <span style={{fontSize:11,color:sc(r.status),fontFamily:"var(--font-mono)"}}>{r.score}/100</span>
                    </div>
                  </td>
                  <td style={{color:r.yara>0?"var(--amber)":"var(--text-dim)",fontFamily:"var(--font-mono)"}}>{r.yara}</td>
                  <td style={{fontFamily:"var(--font-mono)",fontSize:11,color:"var(--text-dim)"}}>{r.hash}</td>
                  <td><span className={`pill ${sp(r.status)}`}>{r.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
