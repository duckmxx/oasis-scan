import flask
from scanner import scan as run_scan

app = flask.Flask(__name__, template_folder="templates", static_folder="static")


@app.route("/")
def dashboard():
    return flask.render_template("index.html")


@app.route("/login")
def login():
    return flask.render_template("login.html")


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
