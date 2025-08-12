from flask import Flask, request, session, render_template
from datetime import datetime, timedelta
import uuid, json, os
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(16))

KEYS_FILE = "keys.json"
if not os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, "w") as f:
        json.dump({}, f)

ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

GLOBAL_TOKEN = "supersecrettoken123"  # Fixed, reuseable

def load_keys():
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(data):
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f)

@app.route("/genkey")
def genkey():
    if request.args.get("access") != GLOBAL_TOKEN:
        return render_template("error.html", message="Invalid link"), 403

    if session.get("got_key"):
        return render_template("error.html", message="Key already issued"), 403

    keys = load_keys()
    new_key = str(uuid.uuid4())
    expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    keys[new_key] = {"expires": expires, "used": False}
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()
    session["got_key"] = True
    return render_template("keygen.html", key=encrypted_key, expires=expires)

@app.route("/verify")
def verify():
    provided = request.args.get("key", "")
    try:
        decrypted = cipher.decrypt(provided.encode()).decode()
    except Exception:
        return {"valid": False, "reason": "Invalid key"}, 400

    keys = load_keys()
    info = keys.get(decrypted)
    if not info:
        return {"valid": False, "reason": "Key not found"}, 404
    if info["used"]:
        return {"valid": False, "reason": "Already used"}, 403
    if datetime.fromisoformat(info["expires"]) < datetime.utcnow():
        return {"valid": False, "reason": "Expired"}, 403

    info["used"] = True
    save_keys(keys)
    return {"valid": True}

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", message="Forbidden"), 403

if __name__ == "__main__":
    app.run(debug=True)
