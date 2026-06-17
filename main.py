import json
import flask
from scanner import scan as run_scan
from cve_lookup import lookup_cves
from integrity_check import run_integrity
from config import (
    FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN, FIREBASE_PROJECT,
    FIREBASE_STORAGE_BUCKET, FIREBASE_MESSAGING_ID, FIREBASE_APP_ID,
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
