from flask import Flask, request, session, render_template, jsonify
from datetime import datetime, timedelta
import uuid, json, os
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(16))

KEYS_FILE = "keys.json"
if not os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, "w") as f:
        json.dump({}, f)

# Use a fixed Fernet key; keep it safe and consistent
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

GLOBAL_TOKEN = os.getenv("GLOBAL_TOKEN", "supersecrettoken123")

def load_keys():
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(data):
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f)

@app.route("/genkey")
def genkey():
    if request.args.get("access") != GLOBAL_TOKEN:
        return render_template("error.html", message="Invalid access token"), 403

    issued_keys = session.get("issued_keys", [])
    now = datetime.utcnow()

    # Clean keys issued in last 24 hours
    issued_keys = [datetime.fromisoformat(ts) for ts in issued_keys]
    issued_keys = [ts for ts in issued_keys if now - ts < timedelta(hours=24)]

    if len(issued_keys) >= 4:
        return render_template("error.html", message="Daily key limit reached (4 keys max)"), 403

    keys = load_keys()
    new_key = str(uuid.uuid4())
    expires = (now + timedelta(hours=24)).isoformat()
    keys[new_key] = {"expires": expires, "used": False}
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()

    issued_keys.append(now)
    session["issued_keys"] = [ts.isoformat() for ts in issued_keys]

    return render_template("keygen.html", key=encrypted_key, expires=expires)

@app.route("/verify")
def verify_key():
    encrypted_key = request.args.get("token")  # expects ?token=...

    if not encrypted_key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    try:
        decrypted_key = cipher.decrypt(encrypted_key.encode()).decode()
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid token or decryption failed"}), 400

    keys = load_keys()
    key_info = keys.get(decrypted_key)
    if not key_info:
        return jsonify({"valid": False, "reason": "Token not found"}), 404

    now = datetime.utcnow()
    expires = datetime.fromisoformat(key_info["expires"])

    if now > expires:
        return jsonify({"valid": False, "reason": "Token expired"}), 403

    if key_info.get("used"):
        return jsonify({"valid": False, "reason": "Token already used"}), 403

    # Mark key as used
    key_info["used"] = True
    save_keys(keys)

    return jsonify({"valid": True, "reason": "Token verified successfully"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
