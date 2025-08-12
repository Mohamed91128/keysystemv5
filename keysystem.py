from flask import Flask, request, jsonify, render_template, session
from datetime import datetime, timedelta
import uuid
import json
import os
import threading
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder="templates")
# Use a secure secret key for sessions
app.secret_key = os.getenv("FLASK_SECRET_KEY", "replace_with_a_strong_secret")

# Local writable storage directory
STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

KEYS_FILE = os.path.join(STORAGE_DIR, "keys.json")

# Encryption key must match exactly with client app
ENCRYPTION_KEY = os.getenv(
    "ENCRYPTION_KEY",
    "hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
).encode()
cipher = Fernet(ENCRYPTION_KEY)

# Shared global token for short link access
GLOBAL_TOKEN = os.getenv("GLOBAL_TOKEN", "supersecrettoken123")

_storage_lock = threading.Lock()

def _read_json_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return {}

def _write_json_file(path: str, data: dict):
    with _storage_lock:
        with open(path, "w") as f:
            json.dump(data, f)

def load_keys() -> dict:
    return _read_json_file(KEYS_FILE)

def save_keys(keys: dict):
    _write_json_file(KEYS_FILE, keys)

@app.route("/genkey")
def genkey():
    access = request.args.get("access", "")
    if access != GLOBAL_TOKEN:
        return render_template("error.html", message="Invalid access token"), 403

    if session.get("got_key"):
        return render_template("error.html", message="You already received a key"), 403

    keys = load_keys()
    new_key = str(uuid.uuid4())
    expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    keys[new_key] = {"expires": expiration, "used": False}
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()
    # Mark session so user can't refresh to get a new key
    session["got_key"] = True
    return render_template("keygen.html", key=encrypted_key, expires=expiration)

@app.route("/verify")
def verify_key():
    provided_key = request.args.get("key")
    if not provided_key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    decrypted = None
    try:
        decrypted = cipher.decrypt(provided_key.encode()).decode()
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid encrypted key"}), 400

    keys = load_keys()
    if decrypted not in keys:
        return jsonify({"valid": False, "reason": "Key not found"}), 404

    info = keys[decrypted]
    if info.get("used"):
        return jsonify({"valid": False, "reason": "Key already used"}), 403

    if datetime.fromisoformat(info["expires"]) < datetime.utcnow():
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    info["used"] = True
    save_keys(keys)
    return jsonify({"valid": True, "admin": False})

@app.route("/adminkey")
def adminkey():
    encrypted = cipher.encrypt(GLOBAL_TOKEN.encode()).decode()
    return jsonify({"encrypted_admin_key": encrypted})

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", message="Forbidden"), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
