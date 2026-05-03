from flask import Flask, jsonify, send_file, abort
import os, hashlib

app = Flask(__name__)

FIRMWARE_DIR = os.path.join(os.path.dirname(__file__), "..", "firmware")
CURRENT_VERSION = "1.1.0"   # version disponible sur le serveur

def firmware_path():
    return os.path.join(FIRMWARE_DIR, f"fw_{CURRENT_VERSION}.bin")

def firmware_sha256():
    path = firmware_path()
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# ── /version ──────────────────────────────
@app.route("/version")
def version():
    sha = firmware_sha256()
    sig_exists = os.path.exists(firmware_path() + ".sig")
    return jsonify({
        "version": CURRENT_VERSION,
        "sha256":  sha if sha else "no_firmware",
        "signed":  sig_exists,
        "url":     f"https://192.168.137.26:5000/firmware"
    })
# ── /firmware ─────────────────────────────
@app.route("/firmware")
def firmware():
    path = firmware_path()
    if not os.path.exists(path):
        abort(404, description="firmware introuvable")
    return send_file(path, mimetype="application/octet-stream")

# ── /firmware/sig ─────────────────────────
@app.route("/firmware/sig")
def firmware_sig():
    path = firmware_path() + ".sig"
    if not os.path.exists(path):
        abort(404, description="signature introuvable")
    return send_file(path, mimetype="application/octet-stream")

# ── /health ───────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "server": "ota-pi"})

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=(
            "certs/server.crt",
            "certs/server.key"
        )
    )
