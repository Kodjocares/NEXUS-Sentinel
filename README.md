# ⬡ NEXUS Sentinel v2.0

> AI-powered antivirus, live threat monitoring, and intrusion detection dashboard.  
> React + Vite (frontend) · Flask + YARA (backend) · Claude Sonnet (AI engine).

![License](https://img.shields.io/badge/license-MIT-teal) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![React](https://img.shields.io/badge/react-18-61dafb) ![YARA](https://img.shields.io/badge/YARA-4.5-orange)

---

## Features

| Module | Description |
|---|---|
| **Live Threat Feed** | Real-time event stream — severity, source IP, target, engine status |
| **File Scanner** | Drag-and-drop upload → YARA rule engine + VirusTotal hash lookup |
| **YARA Rules Manager** | GUI editor to create, toggle, and deploy custom detection rules |
| **AI Threat Analysis** | Claude Sonnet — attack vector, impact, remediation, confidence score |
| **PyForensix Terminal** | Integrated terminal proxying commands to PyForensix v3.0 |
| **Network Sparkline** | Live traffic chart updated per detection event |

---

## Quick Start

### 1 — Clone & Install

```bash
git clone https://github.com/Kodjocares/nexus-sentinel.git
cd nexus-sentinel
npm install
cd backend && pip install -r requirements.txt && cd ..
```

### 2 — Configure

```bash
cp .env.example .env
# Fill in API keys
```

| Variable | Required | Purpose |
|---|---|---|
| `VITE_ANTHROPIC_API_KEY` | Yes | Claude AI threat analysis |
| `VIRUSTOTAL_API_KEY` | Optional | File hash reputation |
| `ABUSEIPDB_API_KEY` | Optional | IP abuse scoring |

### 3 — Run

```bash
npm run dev        # Terminal A — Vite frontend on :5173
cd backend && python app.py   # Terminal B — Flask on :5000
# Or: npm start    # runs both with concurrently
```

Open **http://localhost:5173**

---

## Project Structure

```
nexus-sentinel/
├── src/
│   ├── App.jsx                  # Root shell + sidebar navigation
│   ├── App.css                  # Design system (IBM Plex Mono, dark theme)
│   ├── main.jsx
│   └── components/
│       ├── LiveFeed.jsx         # Streaming threat table + network sparkline
│       ├── FileScanner.jsx      # Drag-drop upload + YARA scan results
│       ├── YaraPanel.jsx        # Rule list, toggle switches, inline editor
│       └── AIAnalysis.jsx       # Claude-powered analysis + follow-up Q&A
├── backend/
│   ├── app.py                   # Flask API — scan, YARA, IP lookup, forensix
│   ├── requirements.txt
│   └── yara_rules/
│       └── threats.yar          # Built-in detection rules
├── public/favicon.svg
├── .env.example
├── vite.config.js
└── package.json
```

---

## Backend API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Engine status + integration flags |
| POST | `/api/scan` | Scan uploaded files (multipart/form-data) |
| GET | `/api/ip/lookup?ip=X` | AbuseIPDB IP reputation |
| GET | `/api/yara/rules` | List all YARA rules |
| GET/PUT | `/api/yara/rules/:name` | Get or save a rule |
| POST | `/api/forensix` | Proxy command to PyForensix |

---

## PyForensix Integration

Point the terminal panel at your running PyForensix v3.0 instance:

```python
# backend/app.py — forensix_cmd()
import subprocess
result = subprocess.run(
    ["python", "../pyforensix/pyforensix.py", "--scan", data["target"]],
    capture_output=True, text=True
)
return jsonify({"output": result.stdout})
```

---

## YARA Rules

Drop `.yar` files into `backend/yara_rules/` — compiled and loaded at startup.  
Edit live from the **YARA Rules Manager** tab. Built-in rules cover:  
ransomware · PHP webshells · SQL injection · keylogger APIs · obfuscated PowerShell.

---

## Roadmap

- [ ] Packet capture tab (Scapy live interface)
- [ ] MalwareBazaar + Shodan feeds
- [ ] Email/Slack alerts on critical events
- [ ] LangGraph multi-agent pentest pipeline (APA v2 bridge)
- [ ] NEXUS Mobile Forensics bridge

---

## License

MIT © 2025 Village Man / Jah Kodjo — NEXUS Sentinel
