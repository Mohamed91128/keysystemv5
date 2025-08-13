from flask import Flask, request, session, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timedelta
import uuid, json, os
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(16))
CORS(app)  # Enable CORS for frontend access

# File to store keys
KEYS_FILE = "keys.json"
if not os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, "w") as f:
        json.dump({}, f)

# Hardcoded encryption key (must match the one used to encrypt keys)
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

# Global access token for /genkey
GLOBAL_TOKEN = os.getenv("GLOBAL_TOKEN", "supersecrettoken123")


# Load and save key helpers
def load_keys():
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(data):
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f)


# Generate a key (HTML response)
@app.route("/genkey")
def genkey():
    if request.args.get("access") != GLOBAL_TOKEN:
        return render_template("error.html", message="Invalid access token"), 403

    issued_keys = session.get("issued_keys", [])
    now = datetime.utcnow()

    # Filter keys issued in the last 24 hours
    issued_keys = [datetime.fromisoformat(ts) for ts in issued_keys]
    issued_keys = [ts for ts in issued_keys if now - ts < timedelta(hours=24)]

    if len(issued_keys) >= 4:
        return render_template("error.html", message="Daily key limit reached (4 keys max)"), 403

    # Generate key and store
    keys = load_keys()
    new_key = str(uuid.uuid4())
    expires = (now + timedelta(hours=24)).isoformat()
    keys[new_key] = {"expires": expires, "used": False}
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()

    issued_keys.append(now)
    session["issued_keys"] = [ts.isoformat() for ts in issued_keys]

    return render_template("keygen.html", key=encrypted_key, expires=expires)


# Verify a token (JSON API)
@app.route("/verify")
def verify():
    token = request.args.get("token")
    if not token:
        return jsonify({"reason": "No key provided", "valid": False}), 400

    try:
        decrypted_key = cipher.decrypt(token.encode()).decode()
    except Exception as e:
        print(f"[ERROR] Decryption failed: {str(e)}")
        return jsonify({"reason": "Invalid token or decryption failed", "valid": False}), 400

    try:
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
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return jsonify({"reason": "Internal server error", "valid": False}), 500


# Optional: show full traceback on errors (DEV ONLY)
@app.errorhandler(Exception)
def handle_unexpected_error(e):
    import traceback
    return jsonify({
        "reason": "Unhandled server error",
        "error": str(e),
        "trace": traceback.format_exc(),
        "valid": False
    }), 500


# Start Flask app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
