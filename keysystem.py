from flask import Flask, request, session, jsonify
from datetime import datetime, timedelta
import uuid, json, os
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(16))

KEYS_FILE = "keys.json"
if not os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, "w") as f:
        json.dump({}, f)

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
        return jsonify({"reason": "Invalid access token", "valid": False}), 403

    issued_keys = session.get("issued_keys", [])
    now = datetime.utcnow()

    # Remove keys older than 24 hours
    issued_keys = [datetime.fromisoformat(ts) for ts in issued_keys]
    issued_keys = [ts for ts in issued_keys if now - ts < timedelta(hours=24)]

    if len(issued_keys) >= 4:
        return jsonify({"reason": "Daily key limit reached (4 keys max)", "valid": False}), 403

    keys = load_keys()
    new_key = str(uuid.uuid4())
    expires = (now + timedelta(hours=24)).isoformat()
    keys[new_key] = {"expires": expires, "used": False}
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()

    issued_keys.append(now)
    session["issued_keys"] = [ts.isoformat() for ts in issued_keys]

    return jsonify({"key": encrypted_key, "expires": expires, "valid": True})

@app.route("/verify")
def verify():
    token = request.args.get("token")
    if not token:
        return jsonify({"reason": "No key provided", "valid": False}), 400

    try:
        decrypted_key = cipher.decrypt(token.encode()).decode()
    except Exception:
        return jsonify({"reason": "Invalid token or decryption failed", "valid": False}), 400

    keys = load_keys()
    key_info = keys.get(decrypted_key)
    if not key_info:
        return jsonify({"reason": "Token not found", "valid": False}), 404

    now = datetime.utcnow()
    expires = datetime.fromisoformat(key_info["expires"])

    if now > expires:
        return jsonify({"reason": "Token expired", "valid": False}), 403

    if key_info.get("used"):
        return jsonify({"reason": "Token already used", "valid": False}), 403

    # Mark as used
    key_info["used"] = True
    save_keys(keys)

    return jsonify({"reason": "Token verified successfully", "valid": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
