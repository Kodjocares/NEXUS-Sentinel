"""
NEXUS Sentinel — Backend API
Flask server integrating YARA scanning, VirusTotal, AbuseIPDB,
and PyForensix for file analysis and live threat intelligence.

Run:
    pip install -r requirements.txt
    python app.py
"""

import os, hashlib, json, time, threading
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173", "http://localhost:3000"])

UPLOAD_DIR = Path("./uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# ── Optional integrations (gracefully degraded if not installed) ──────────────
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[WARN] yara-python not installed. YARA scanning disabled.")

try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

YARA_RULES_DIR = Path("./yara_rules")


def load_yara_rules():
    """Compile all .yar files in yara_rules/ directory."""
    if not YARA_AVAILABLE:
        return None
    filepaths = {f.stem: str(f) for f in YARA_RULES_DIR.glob("*.yar")}
    if not filepaths:
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except Exception as e:
        print(f"[ERROR] YARA compile: {e}")
        return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def virustotal_lookup(file_hash: str) -> dict:
    """Check a SHA256 hash against VirusTotal API v3."""
    if not (REQUESTS_AVAILABLE and VIRUSTOTAL_KEY):
        return {"available": False}
    try:
        r = req_lib.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "available": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values()),
            }
        return {"available": True, "not_found": True}
    except Exception as e:
        return {"available": False, "error": str(e)}


def abuseipdb_lookup(ip: str) -> dict:
    """Check an IP against AbuseIPDB."""
    if not (REQUESTS_AVAILABLE and ABUSEIPDB_KEY):
        return {"available": False}
    try:
        r = req_lib.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=6,
        )
        if r.status_code == 200:
            d = r.json()["data"]
            return {
                "available": True,
                "abuseScore": d.get("abuseConfidenceScore", 0),
                "totalReports": d.get("totalReports", 0),
                "countryCode": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}
    return {"available": False}


def score_from_yara(matches) -> int:
    """Convert YARA matches to a 0-100 threat score."""
    if not matches:
        return 0
    score = 0
    for m in matches:
        meta = m.meta if hasattr(m, "meta") else {}
        sev = meta.get("severity", "medium")
        score += {"critical": 35, "high": 25, "medium": 15, "low": 5}.get(sev, 10)
    return min(score, 99)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "yara": YARA_AVAILABLE,
        "virustotal": bool(VIRUSTOTAL_KEY),
        "abuseipdb": bool(ABUSEIPDB_KEY),
        "timestamp": int(time.time()),
    })


@app.route("/api/scan", methods=["POST"])
def scan_files():
    """Scan uploaded files with YARA and optionally VirusTotal."""
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400

    files   = request.files.getlist("files")
    rules   = load_yara_rules()
    results = []

    for f in files:
        if not f.filename:
            continue
        dest = UPLOAD_DIR / f.filename
        f.save(dest)

        file_hash = sha256_file(dest)
        yara_hits = []
        yara_count = 0

        if rules:
            try:
                matches = rules.match(str(dest))
                yara_hits  = [m.rule for m in matches]
                yara_count = len(yara_hits)
            except Exception as e:
                print(f"[YARA] {f.filename}: {e}")

        score = score_from_yara(yara_hits) if yara_hits else 0

        vt = virustotal_lookup(file_hash)
        if vt.get("available") and not vt.get("not_found"):
            vt_mal = vt.get("malicious", 0)
            vt_sus = vt.get("suspicious", 0)
            vt_score = min(int((vt_mal / max(vt.get("total", 1), 1)) * 100), 99)
            score = max(score, vt_score)

        if score >= 70:
            status = "malware"
        elif score >= 30 or yara_count > 0:
            status = "suspicious"
        else:
            status = "clean"

        results.append({
            "name":  f.filename,
            "size":  _fmt_bytes(dest.stat().st_size),
            "hash":  file_hash[:8] + "..." + file_hash[-4:],
            "full_hash": file_hash,
            "score": score,
            "yara":  yara_count,
            "yara_rules": yara_hits,
            "status": status,
            "virustotal": vt,
        })

        dest.unlink(missing_ok=True)

    return jsonify({"results": results, "count": len(results)})


@app.route("/api/ip/lookup", methods=["GET"])
def ip_lookup():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    return jsonify(abuseipdb_lookup(ip))


@app.route("/api/yara/rules", methods=["GET"])
def list_rules():
    rules = []
    for f in YARA_RULES_DIR.glob("*.yar"):
        rules.append({"name": f.stem, "file": f.name, "size": f.stat().st_size})
    return jsonify({"rules": rules})


@app.route("/api/yara/rules/<name>", methods=["GET", "PUT"])
def rule_crud(name):
    path = YARA_RULES_DIR / f"{name}.yar"
    if request.method == "GET":
        if not path.exists():
            return jsonify({"error": "not found"}), 404
        return jsonify({"name": name, "content": path.read_text()})
    if request.method == "PUT":
        data = request.get_json()
        content = data.get("content", "")
        if YARA_AVAILABLE:
            try:
                yara.compile(source=content)
            except Exception as e:
                return jsonify({"error": f"YARA syntax error: {e}"}), 400
        YARA_RULES_DIR.mkdir(exist_ok=True)
        path.write_text(content)
        return jsonify({"status": "saved", "name": name})


@app.route("/api/forensix", methods=["POST"])
def forensix_cmd():
    """
    Proxy commands to PyForensix.
    Body: { "command": "scan", "target": "/path", "args": [] }
    """
    data = request.get_json() or {}
    cmd  = data.get("command", "")
    # In production, invoke PyForensix subprocess here.
    # For demo, echo back the command.
    return jsonify({
        "status": "dispatched",
        "command": cmd,
        "message": f"PyForensix received: {cmd}. Integrate subprocess call in production.",
    })


def _fmt_bytes(n):
    if n < 1024:       return f"{n} B"
    if n < 1_048_576:  return f"{n/1024:.1f} KB"
    return f"{n/1_048_576:.1f} MB"


if __name__ == "__main__":
    YARA_RULES_DIR.mkdir(exist_ok=True)
    print(f"[NEXUS Sentinel] Backend starting on http://0.0.0.0:5000")
    print(f"  YARA:        {'✓' if YARA_AVAILABLE else '✗ (pip install yara-python)'}")
    print(f"  VirusTotal:  {'✓' if VIRUSTOTAL_KEY else '✗ (set VIRUSTOTAL_API_KEY)'}")
    print(f"  AbuseIPDB:   {'✓' if ABUSEIPDB_KEY else '✗ (set ABUSEIPDB_API_KEY)'}")
    app.run(host="0.0.0.0", port=5000, debug=True)
