import { useState } from "react";

const BUILTIN_RULES = [
  {
    name: "ransomware_generic",
    category: "Ransomware",
    active: true,
    hits: 12,
    rule: `rule ransomware_generic {
  meta:
    description = "Detects generic ransomware behavior"
    severity     = "critical"
    author       = "NEXUS Sentinel"
  strings:
    $enc1 = "CryptEncrypt" ascii
    $enc2 = "AES256"       ascii
    $note = "YOUR FILES ARE ENCRYPTED" nocase
    $ext1 = ".locked" ascii
    $ext2 = ".enc"    ascii
  condition:
    2 of ($enc*) and 1 of ($note, $ext*)
}`,
  },
  {
    name: "webshell_detection",
    category: "Webshell",
    active: true,
    hits: 3,
    rule: `rule webshell_detection {
  meta:
    description = "Detects common PHP/ASP webshells"
    severity     = "high"
    author       = "NEXUS Sentinel"
  strings:
    $php1 = "<?php" ascii
    $cmd1 = "eval(base64_decode" ascii
    $cmd2 = "system($_GET"       ascii
    $cmd3 = "passthru("          ascii
    $cmd4 = "shell_exec("        ascii
  condition:
    $php1 and any of ($cmd*)
}`,
  },
  {
    name: "sql_injection_payload",
    category: "Injection",
    active: true,
    hits: 27,
    rule: `rule sql_injection_payload {
  meta:
    description = "Detects SQL injection patterns in files/payloads"
    severity     = "high"
    author       = "NEXUS Sentinel"
  strings:
    $s1 = "' OR '1'='1"    nocase
    $s2 = "UNION SELECT"   nocase
    $s3 = "DROP TABLE"     nocase
    $s4 = "--"             ascii
    $s5 = "xp_cmdshell"   nocase
  condition:
    2 of them
}`,
  },
  {
    name: "keylogger_behavior",
    category: "Spyware",
    active: false,
    hits: 1,
    rule: `rule keylogger_behavior {
  meta:
    description = "Detects keylogger API calls"
    severity     = "critical"
    author       = "NEXUS Sentinel"
  strings:
    $api1 = "SetWindowsHookEx"  ascii wide
    $api2 = "GetAsyncKeyState"  ascii wide
    $api3 = "GetKeyboardState"  ascii wide
    $log  = "keylog"            nocase
  condition:
    2 of ($api*) or ($log and 1 of ($api*))
}`,
  },
];

export default function YaraPanel() {
  const [rules,    setRules]    = useState(BUILTIN_RULES);
  const [selected, setSelected] = useState(0);
  const [editing,  setEditing]  = useState(false);
  const [draft,    setDraft]    = useState("");
  const [newName,  setNewName]  = useState("");
  const [newCat,   setNewCat]   = useState("Custom");
  const [creating, setCreating] = useState(false);
  const [saved,    setSaved]    = useState(false);

  const cur = rules[selected];

  const toggle = i => setRules(p => p.map((r,j)=>j===i?{...r,active:!r.active}:r));

  const startEdit = () => { setDraft(cur.rule); setEditing(true); setSaved(false); };
  const saveEdit  = () => {
    setRules(p=>p.map((r,i)=>i===selected?{...r,rule:draft}:r));
    setEditing(false); setSaved(true);
    setTimeout(()=>setSaved(false),2000);
  };

  const addRule = () => {
    if (!newName.trim()) return;
    const r = {
      name: newName.toLowerCase().replace(/\s+/g,"_"),
      category: newCat,
      active: true,
      hits: 0,
      rule: `rule ${newName.toLowerCase().replace(/\s+/g,"_")} {\n  meta:\n    description = "Custom rule"\n    author       = "NEXUS Sentinel"\n  strings:\n    $s1 = "" ascii\n  condition:\n    $s1\n}`,
    };
    setRules(p=>[...p,r]);
    setSelected(rules.length);
    setCreating(false);
    setNewName(""); setNewCat("Custom");
    setDraft(r.rule); setEditing(true);
  };

  const catColor = c => c==="Ransomware"?"var(--red)":c==="Webshell"?"var(--amber)":c==="Injection"?"var(--purple)":c==="Spyware"?"var(--teal)":"var(--blue)";

  return (
    <div>
      <div className="pane-head">
        <h2>YARA Rules Manager</h2>
        <div style={{display:"flex",gap:8}}>
          <span className="pill info">{rules.length} rules</span>
          <span className="pill live">{rules.filter(r=>r.active).length} active</span>
        </div>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"260px 1fr",gap:16}}>
        {/* Rule list */}
        <div>
          <div style={{marginBottom:8}}>
            <button className="btn primary" style={{width:"100%",marginBottom:6}} onClick={()=>setCreating(c=>!c)}>
              {creating?"✕ Cancel":"+ New Rule"}
            </button>
            {creating && (
              <div style={{padding:12,background:"var(--bg1)",border:"1px solid var(--border)",borderRadius:"var(--r)",marginBottom:6}}>
                <div style={{marginBottom:8}}>
                  <input placeholder="Rule name" value={newName} onChange={e=>setNewName(e.target.value)} style={{marginBottom:6}} />
                  <select value={newCat} onChange={e=>setNewCat(e.target.value)}>
                    {["Ransomware","Webshell","Injection","Spyware","Network","Custom"].map(c=><option key={c}>{c}</option>)}
                  </select>
                </div>
                <button className="btn primary" style={{width:"100%"}} onClick={addRule}>Create ↗</button>
              </div>
            )}
          </div>
          {rules.map((r,i)=>(
            <div key={i} onClick={()=>{setSelected(i);setEditing(false);}}
              style={{padding:"10px 12px",marginBottom:4,borderRadius:"var(--r)",cursor:"pointer",
                background:selected===i?"var(--bg3)":"var(--bg1)",
                border:`1px solid ${selected===i?"var(--teal)":"var(--border)"}`,
                transition:"all 0.15s"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                <span style={{fontFamily:"var(--font-mono)",fontSize:12,fontWeight:500,color:selected===i?"var(--teal)":"var(--text-primary)"}}>{r.name}</span>
                <label style={{display:"flex",alignItems:"center",gap:4,cursor:"pointer"}} onClick={e=>{e.stopPropagation();toggle(i);}}>
                  <div style={{width:28,height:15,borderRadius:8,background:r.active?"var(--teal)":"var(--bg4)",transition:"background 0.2s",position:"relative"}}>
                    <div style={{position:"absolute",top:2,left:r.active?13:2,width:11,height:11,borderRadius:"50%",background:"white",transition:"left 0.2s"}} />
                  </div>
                </label>
              </div>
              <div style={{display:"flex",justifyContent:"space-between"}}>
                <span style={{fontSize:11,color:catColor(r.category)}}>{r.category}</span>
                <span style={{fontSize:11,color:"var(--text-dim)",fontFamily:"var(--font-mono)"}}>{r.hits} hits</span>
              </div>
            </div>
          ))}
        </div>

        {/* Rule editor */}
        <div>
          <div style={{display:"flex",gap:8,marginBottom:12,alignItems:"center"}}>
            <span style={{fontFamily:"var(--font-mono)",fontSize:13,color:"var(--teal)",fontWeight:500}}>{cur?.name}</span>
            <span style={{fontSize:11,color:catColor(cur?.category),fontFamily:"var(--font-mono)"}}>{cur?.category}</span>
            <div style={{marginLeft:"auto",display:"flex",gap:6}}>
              {!editing
                ? <button className="btn" onClick={startEdit}>Edit Rule</button>
                : <>
                    <button className="btn primary" onClick={saveEdit}>Save ↗</button>
                    <button className="btn" onClick={()=>setEditing(false)}>Cancel</button>
                  </>
              }
            </div>
          </div>
          {saved && <div style={{marginBottom:8,padding:"6px 10px",background:"var(--green-bg)",border:"1px solid rgba(62,207,136,0.3)",borderRadius:"var(--r)",fontSize:12,color:"var(--green)",fontFamily:"var(--font-mono)"}}>✓ Rule saved</div>}
          <textarea className="yara-editor" value={editing?draft:cur?.rule} readOnly={!editing}
            onChange={e=>setDraft(e.target.value)} style={{minHeight:280}} spellCheck={false} />
          <div style={{marginTop:10,padding:"10px 12px",background:"var(--bg1)",border:"1px solid var(--border)",borderRadius:"var(--r)",fontSize:12,color:"var(--text-dim)",fontFamily:"var(--font-mono)"}}>
            Rule stored in <span style={{color:"var(--teal)"}}>backend/yara_rules/{cur?.name}.yar</span> — loaded by PyForensix engine at runtime.
          </div>
        </div>
      </div>
    </div>
  );
}
