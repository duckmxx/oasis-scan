import asyncio
import http.client
import io
import json
import os as _os
import urllib.parse
import urllib.request as _urllib_req
import uuid
import flask
from datetime import datetime, timezone

try:
    import edge_tts as _edge_tts
    _TTS_OK = True
except ImportError:
    _TTS_OK = False
from cve_lookup import lookup_cves
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


# NOTE: host scanning has been removed from the server. In production this app
# runs on a DigitalOcean droplet and must never scan the machine it runs on.
# All device/scan data is collected by the desktop agents (gui.py) and synced to
# Firestore; this server only serves the dashboard, proxies AI/TTS, and manages
# agent tokens. (Former endpoints: /api/scan, /api/integrity.)


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


@app.route("/api/stt", methods=["POST"])
def api_stt():
    audio = flask.request.files.get("audio")
    if not audio:
        return flask.jsonify({"ok": False, "error": "No audio file"}), 400

    audio_bytes = audio.read()
    filename    = audio.filename or "recording.webm"
    boundary    = "----WBoundary" + _os.urandom(8).hex()

    body  = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="model"\r\n\r\n'
    body += b"whisper-large-v3-turbo\r\n"
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b"Content-Type: audio/webm\r\n\r\n"
    body += audio_bytes + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    conn = None
    try:
        conn = http.client.HTTPSConnection("api.groq.com", 443, timeout=30)
        conn.request("POST", "/openai/v1/audio/transcriptions", body=body, headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type":  f"multipart/form-data; boundary={boundary}",
        })
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
        text = data.get("text", "").strip()
        return flask.jsonify({"ok": True, "text": text})
    except Exception as e:
        return flask.jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if conn:
            try: conn.close()
            except Exception: pass


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
_BASE_DIR   = _os.path.dirname(_os.path.abspath(__file__))
_TOKEN_FILE = _os.path.join(_BASE_DIR, 'agent_tokens.json')


def _load_tokens() -> dict:
    try:
        with open(_TOKEN_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_tokens(tokens: dict):
    with open(_TOKEN_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)


def _verify_firebase_token(id_token: str):
    """Return uid if the Firebase ID token is valid, else None."""
    try:
        url  = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={FIREBASE_API_KEY}"
        body = json.dumps({"idToken": id_token}).encode()
        req  = _urllib_req.Request(url, data=body,
                                   headers={"Content-Type": "application/json"})
        with _urllib_req.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            users = data.get("users", [])
            if users:
                return users[0].get("localId")
    except Exception:
        pass
    return None


def _refresh_firebase_token(refresh_token: str):
    """Exchange a Firebase refresh token for (id_token, uid). Returns (None, None) on failure."""
    try:
        url  = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_API_KEY}"
        body = urllib.parse.urlencode({
            "grant_type":    "refresh_token",
            "refresh_token": refresh_token,
        }).encode()
        req  = _urllib_req.Request(url, data=body, headers={
            "Content-Type": "application/x-www-form-urlencoded",
        })
        with _urllib_req.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("id_token"), data.get("user_id")
    except Exception:
        pass
    return None, None


def _firestore_write_token(id_token: str, uid: str, token: str, name: str, refresh_token: str):
    """Write full token data to Firestore — Firestore is the durable source of truth."""
    url = (f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT}"
           f"/databases/(default)/documents/users/{uid}/agent_tokens/{token}")
    doc = {"fields": {
        "name":          {"stringValue": name},
        "uid":           {"stringValue": uid},
        "refresh_token": {"stringValue": refresh_token},
        "created":       {"stringValue": datetime.now(timezone.utc).isoformat()},
    }}
    try:
        req = _urllib_req.Request(
            url, data=json.dumps(doc).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {id_token}"},
            method="PATCH")
        with _urllib_req.urlopen(req, timeout=10):
            pass
    except Exception:
        pass  # best-effort; local file is fallback


def _firestore_read_token(id_token: str, uid: str, token: str) -> dict | None:
    """Fetch a single token document from Firestore. Returns entry dict or None."""
    url = (f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT}"
           f"/databases/(default)/documents/users/{uid}/agent_tokens/{token}")
    req = _urllib_req.Request(url, headers={"Authorization": f"Bearer {id_token}"})
    try:
        with _urllib_req.urlopen(req, timeout=10) as resp:
            fields = json.loads(resp.read()).get("fields", {})
            rt     = fields.get("refresh_token", {}).get("stringValue", "")
            if not rt:
                return None
            return {
                "uid":           uid,
                "name":          fields.get("name", {}).get("stringValue", "Agent"),
                "refresh_token": rt,
                "created":       fields.get("created", {}).get("stringValue", ""),
            }
    except Exception:
        return None


@app.route("/api/info")
def api_info():
    return flask.jsonify({"ok": True, "model": AI_MODEL})


@app.route("/api/agent-auth", methods=["POST"])
def api_agent_auth():
    """Exchange an agent token for a Firebase ID token (used by gui.py)."""
    body  = flask.request.get_json(force=True) or {}
    token = (body.get("token") or "").strip()
    if not token:
        return flask.jsonify({"ok": False, "error": "token required"}), 400

    tokens = _load_tokens()
    entry  = tokens.get(token)

    # Local cache miss — try to restore from Firestore using the stored fallback credential.
    # This handles server restarts where agent_tokens.json was lost.
    if not entry:
        fallback = tokens.get("_fallback")
        if fallback:
            fb_id_token, _ = _refresh_firebase_token(fallback["refresh_token"])
            if fb_id_token:
                entry = _firestore_read_token(fb_id_token, fallback["uid"], token)
                if entry:
                    # Repopulate local cache
                    tokens[token] = entry
                    _save_tokens(tokens)

    if not entry:
        return flask.jsonify({"ok": False, "error": "Invalid token"}), 401

    id_token, uid = _refresh_firebase_token(entry["refresh_token"])
    if not id_token:
        return flask.jsonify({
            "ok": False,
            "error": "Could not refresh credentials — the token owner may have changed their password",
        }), 401
    return flask.jsonify({"ok": True, "id_token": id_token, "uid": uid})


@app.route("/api/admin/create-token", methods=["POST"])
def api_admin_create_token():
    """Create a new agent token for the authenticated Firebase user."""
    auth_header = flask.request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return flask.jsonify({"ok": False, "error": "Unauthorized"}), 401
    uid = _verify_firebase_token(auth_header[7:])
    if not uid:
        return flask.jsonify({"ok": False, "error": "Invalid Firebase token"}), 401

    body          = flask.request.get_json(force=True) or {}
    name          = (body.get("name") or "Agent").strip()[:50]
    refresh_token = (body.get("refresh_token") or "").strip()
    if not refresh_token:
        return flask.jsonify({"ok": False, "error": "refresh_token required"}), 400

    token   = uuid.uuid4().hex
    created = datetime.now(timezone.utc).isoformat()
    tokens  = _load_tokens()
    tokens[token] = {
        "uid":           uid,
        "name":          name,
        "refresh_token": refresh_token,
        "created":       created,
    }
    # Keep a fallback credential so /api/agent-auth can read Firestore if this file is lost
    tokens["_fallback"] = {
        "uid":           uid,
        "refresh_token": refresh_token,
        "updated":       created,
    }
    _save_tokens(tokens)

    # Write full token data to Firestore — this is the durable source of truth.
    # The local file is a cache; Firestore survives server restarts and disk loss.
    _firestore_write_token(auth_header[7:], uid, token, name, refresh_token)

    return flask.jsonify({"ok": True, "token": token, "name": name})


@app.route("/api/admin/revoke-token", methods=["POST"])
def api_admin_revoke_token():
    """Revoke an agent token (must be called by the token's owner)."""
    auth_header = flask.request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return flask.jsonify({"ok": False, "error": "Unauthorized"}), 401
    uid = _verify_firebase_token(auth_header[7:])
    if not uid:
        return flask.jsonify({"ok": False, "error": "Invalid Firebase token"}), 401

    body  = flask.request.get_json(force=True) or {}
    token = (body.get("token") or "").strip()
    tokens = _load_tokens()
    entry  = tokens.get(token)
    if not entry or entry.get("uid") != uid:
        return flask.jsonify({"ok": False, "error": "Token not found"}), 404

    del tokens[token]
    _save_tokens(tokens)

    # Delete from Firestore too
    fs_url = (f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT}"
              f"/databases/(default)/documents/users/{uid}/agent_tokens/{token}")
    try:
        req = _urllib_req.Request(fs_url, headers={"Authorization": f"Bearer {auth_header[7:]}"},
                                  method="DELETE")
        with _urllib_req.urlopen(req, timeout=10):
            pass
    except Exception:
        pass  # best-effort; local file is already updated

    return flask.jsonify({"ok": True})


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
