import flask

app = flask.Flask(__name__, template_folder="templates", static_folder="static")


@app.route("/")
def dashboard():
    return flask.render_template("index.html")


@app.route("/api/status")
def status():
    return flask.jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
