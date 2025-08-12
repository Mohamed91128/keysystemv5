from flask import Flask, request, session, render_template
from datetime import datetime, timedelta
import uuid, json, os
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(16))

# File to store keys
KEYS_FILE = "keys.json"
if not os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, "w") as f:
        json.dump({}, f)

# Hardcoded encryption key (must be securely generated and stored in prod)
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

# Global access token to control key generation
GLOBAL_TOKEN = os.getenv("GLOBAL_TOKEN", "supersecrettoken123")

# Load keys from file
def load_keys():
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

# Save keys to file
def save_keys(data):
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f)

# Key generation route
@app.route("/genkey")
def genkey():
    if request.args.get("access") != GLOBAL_TOKEN:
        return render_template("error.html", message="Invalid access token"), 403

    issued_keys = session.get("issued_keys", [])
    now = datetime.utcnow()

    # Keep only keys from the last 24 hours
    issued_keys = [datetime.fromisoformat(ts) for ts in issued_keys]
    issued_keys = [ts for ts in issued_keys if now - ts < timedelta(hours=24)]

    if len(issued_keys) >= 4:
        return render_template("error.html", message="Daily key limit reached (4 keys max)"), 403

    # Generate new key
    keys = load_keys()
    new_key = str(uuid.uuid4())
    expires = (now + timedelta(hours=24)).isoformat()
    keys[new_key] = {"expires": expires, "used": False}
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()

    # Save to session
    issued_keys.append(now)
    session["issued_keys"] = [ts.isoformat() for ts in issued_keys]

    return render_template("keygen.html", key=encrypted_key, expires=expires)

# Key verification route
@app.route("/verify")
def verify():
    token = request.args.get("token")
    if not token:
        return render_template("error.html", message="No token provided"), 400

    try:
        decrypted_key = cipher.decrypt(token.encode()).decode()
    except Exception:
        return render_template("error.html", message="Invalid token or decryption failed"), 400

    keys = load_keys()
    key_info = keys.get(decrypted_key)
    if not key_info:
        return render_template("error.html", message="Token not found"), 404

    now = datetime.utcnow()
    expires = datetime.fromisoformat(key_info["expires"])

    if now > expires:
        return render_template("error.html", message="Token expired"), 403

    if key_info.get("used"):
        return render_template("error.html", message="Token already used"), 403

    # Mark as used
    key_info["used"] = True
    save_keys(keys)

    return render_template("success.html", message="Token verified successfully")

# Start the server
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)

