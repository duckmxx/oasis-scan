import asyncio
import http.client
import io
import json
import os as _os
import urllib.parse
import urllib.request as _urllib_req
import flask

try:
    import edge_tts as _edge_tts
    _TTS_OK = True
except ImportError:
    _TTS_OK = False
from scanner import scan as run_scan, get_nmap_scan
from cve_lookup import lookup_cves
from integrity_check import run_integrity
from patchability import assess_patchability
from config import (
    FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN, FIREBASE_PROJECT,
    FIREBASE_STORAGE_BUCKET, FIREBASE_MESSAGING_ID, FIREBASE_APP_ID,
    GROQ_API_KEY, AI_BASE_URL, AI_MODEL,
    TTS_VOICE, TTS_RATE, TTS_PITCH,
    PIPER_TTS_URL,
)

app = flask.Flask(__name__, template_folder="templates", static_folder="static")

_FIREBASE_JSON = json.dumps({
    "apiKey":            FIREBASE_API_KEY,
    "authDomain":        FIREBASE_AUTH_DOMAIN,
    "projectId":         FIREBASE_PROJECT,
    "storageBucket":     FIREBASE_STORAGE_BUCKET,
    "messagingSenderId": FIREBASE_MESSAGING_ID,
    "appId":             FIREBASE_APP_ID,
})


@app.route("/")
def dashboard():
    return flask.render_template("index.html", firebase_json=_FIREBASE_JSON)


@app.route("/login")
def login():
    return flask.render_template("login.html", firebase_json=_FIREBASE_JSON)


@app.route("/api/status")
def status():
    return flask.jsonify({"status": "ok"})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        report = run_scan()
        return flask.jsonify({"ok": True, "report": report})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        report = flask.request.get_json(force=True) or {}
        cves   = lookup_cves(report)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for c in cves:
            s = c.get("severity", "unknown")
            counts[s] = counts.get(s, 0) + 1
        return flask.jsonify({"ok": True, "cves": cves, "counts": counts})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/patchability", methods=["POST"])
def api_patchability():
    """Assess whether each vulnerable package actually has an installable fix."""
    try:
        body   = flask.request.get_json(force=True) or {}
        report = body.get("report") or {}
        cves   = body.get("cves") or []
        return flask.jsonify({"ok": True, "packages": assess_patchability(report, cves)})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/integrity", methods=["POST"])
def api_integrity():
    try:
        report = flask.request.get_json(force=True) or {}
        result = run_integrity(report)
        return flask.jsonify({"ok": True, **result})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/topology", methods=["POST"])
def api_topology():
    try:
        report = flask.request.get_json(force=True) or {}

        # Parse gateway from routing table
        gateway = None
        routes = report.get("network", {}).get("routes") or []
        if isinstance(routes, list):
            for r in routes:
                if isinstance(r, dict) and r.get("dst") == "default":
                    gateway = r.get("gateway")
                    break

        # Parse non-loopback IPs
        my_ips = []
        addresses = report.get("network", {}).get("addresses") or []
        if isinstance(addresses, list):
            for iface in addresses:
                if not isinstance(iface, dict):
                    continue
                ifname = iface.get("ifname", "")
                if ifname.startswith("lo"):
                    continue
                for addr in iface.get("addr_info", []):
                    if isinstance(addr, dict) and addr.get("family") == "inet":
                        my_ips.append({
                            "interface": ifname,
                            "ip":        addr.get("local"),
                            "prefix":    addr.get("prefixlen"),
                        })

        return flask.jsonify({
            "ok":        True,
            "hostname":  (report.get("os") or {}).get("hostname", ""),
            "my_ips":    my_ips,
            "gateway":   gateway,
            "neighbors": report.get("network_neighbors") or [],
        })
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500


def _ai_stream(messages, temperature=0.7, max_tokens=4096):
    """Proxy streaming SSE from Groq's OpenAI-compatible API."""
    parsed = urllib.parse.urlparse(AI_BASE_URL)
    host   = parsed.hostname or "api.groq.com"
    port   = parsed.port or 443
    path   = (parsed.path or "/openai/v1").rstrip("/") + "/chat/completions"
    body   = json.dumps({
        "model":       AI_MODEL,
        "messages":    messages,
        "stream":      True,
        "max_tokens":  max_tokens,
        "temperature": temperature,
    }).encode()
    conn = None
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=180)
        conn.request("POST", path, body=body, headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
        })
        resp = conn.getresponse()
        if resp.status == 429:
            yield f"data: {json.dumps({'error': 'Rate limited — please wait a moment and try again.'})}\n\n"
            return
        if resp.status != 200:
            err = resp.read().decode("utf-8", errors="replace")
            yield f"data: {json.dumps({'error': f'API error {resp.status}: {err}'})}\n\n"
            return
        buf  = b""
        while True:
            chunk = resp.read(512)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line_bytes, buf = buf.split(b"\n", 1)
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if line:
                    yield line + "\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    data        = flask.request.get_json(force=True) or {}
    messages    = data.get("messages", [])
    temperature = float(data.get("temperature", 0.7))
    max_tokens  = int(data.get("max_tokens",   4096))
    if not messages:
        return flask.jsonify({"ok": False, "error": "No messages"}), 400
    # Clamp to safe ranges
    temperature = max(0.0, min(2.0, temperature))
    max_tokens  = max(256, min(16384, max_tokens))
    return flask.Response(
        flask.stream_with_context(_ai_stream(messages, temperature, max_tokens)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/nmap_scan", methods=["POST"])
def api_nmap_scan():
    try:
        data   = flask.request.get_json(force=True) or {}
        subnet = data.get("subnet", "").strip()
        if not subnet:
            return flask.jsonify({"ok": False, "error": "No subnet provided"}), 400
        result = get_nmap_scan(subnet)
        return flask.jsonify({"ok": True, **result})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500


async def _tts_generate(text: str) -> bytes:
    communicate = _edge_tts.Communicate(text, TTS_VOICE, rate=TTS_RATE, pitch=TTS_PITCH)
    buf = io.BytesIO()
    async for chunk in communicate.stream():
        if chunk["type"] == "audio":
            buf.write(chunk["data"])
    return buf.getvalue()


@app.route("/api/ai/complete", methods=["POST"])
def api_ai_complete():
    """Non-streaming single-turn completion — used for structured JSON responses."""
    data        = flask.request.get_json(force=True) or {}
    messages    = data.get("messages", [])
    temperature = float(data.get("temperature", 0.3))
    max_tokens  = int(data.get("max_tokens", 768))
    if not messages:
        return flask.jsonify({"ok": False, "error": "No messages"}), 400
    temperature = max(0.0, min(2.0, temperature))
    max_tokens  = max(64, min(4096, max_tokens))

    parsed = urllib.parse.urlparse(AI_BASE_URL)
    host   = parsed.hostname or "api.groq.com"
    port   = parsed.port or 443
    path   = (parsed.path or "/openai/v1").rstrip("/") + "/chat/completions"
    body   = json.dumps({
        "model":       AI_MODEL,
        "messages":    messages,
        "stream":      False,
        "max_tokens":  max_tokens,
        "temperature": temperature,
    }).encode()
    conn = None
    try:
        conn    = http.client.HTTPSConnection(host, port, timeout=60)
        conn.request("POST", path, body=body, headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
        })
        resp    = conn.getresponse()
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        text    = payload["choices"][0]["message"]["content"]
        return flask.jsonify({"ok": True, "text": text})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.route("/api/tts", methods=["POST"])
def api_tts():
    data = flask.request.get_json(force=True) or {}
    text = data.get("text", "").strip()[:1200]
    if not text:
        return flask.abort(400)

    # ── Primary: local Piper TTS microservice ──────────────────────────────
    speed  = float(data.get("speed",  1.0))
    volume = float(data.get("volume", 1.0))
    # length_scale is inverse of speed (higher = slower in Piper)
    length_scale = max(0.25, min(4.0, 1.0 / max(0.1, speed)))
    volume       = max(0.0,  min(2.0, volume))
    try:
        req = _urllib_req.Request(
            PIPER_TTS_URL,
            data=json.dumps({
                "text":         text,
                "length_scale": length_scale,
                "volume":       volume,
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _urllib_req.urlopen(req, timeout=10) as resp:
            audio = resp.read()
        return flask.Response(audio, mimetype="audio/wav",
                              headers={"Cache-Control": "no-store"})
    except Exception:
        pass  # fall through to cloud fallback

    # ── Fallback: edge-tts (cloud) ─────────────────────────────────────────
    if not _TTS_OK:
        return flask.jsonify({"ok": False,
                              "error": "Piper TTS unreachable and edge-tts not installed"}), 503
    try:
        audio = asyncio.run(_tts_generate(text))
        return flask.Response(audio, mimetype="audio/mpeg",
                              headers={"Cache-Control": "no-store"})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500


_DOWNLOAD_WHITELIST = {"gui.py", "scanner.py", "tts_server.py"}
_BASE_DIR = _os.path.dirname(_os.path.abspath(__file__))


@app.route("/download/<path:filename>")
def download_file(filename):
    if filename not in _DOWNLOAD_WHITELIST:
        return flask.abort(404)
    return flask.send_file(
        _os.path.join(_BASE_DIR, filename),
        as_attachment=True,
        download_name=filename,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
