from flask import Flask, request, session, render_template
from datetime import datetime, timedelta
import uuid, json, os, requests
from cryptography.fernet import Fernet

# === App Setup ===
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(16))

# === Config ===
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

GLOBAL_TOKEN = os.getenv("GLOBAL_TOKEN", "supersecrettoken123")

SHORT_JAMBO_API_TOKEN = os.getenv("SHORT_JAMBO_API_TOKEN", "6e49817e3eab65f2f9b06f8c1319ba768a4ae9c4")
SHORT_JAMBO_ENDPOINT = "https://short-jambo.com/api"

KEYS_FILE = "keys.json"
if not os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, "w") as f:
        json.dump({}, f)

# === Helpers ===
def load_keys():
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(data):
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f)

# === Routes ===
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

@app.route("/create_genkey_link")
def create_genkey_link():
    alias = request.args.get("alias")
    base_url = request.url_root.rstrip("/")
    long_url = f"{base_url}/genkey?access={GLOBAL_TOKEN}"

    params = {
        "api": SHORT_JAMBO_API_TOKEN,
        "url": long_url
    }
    if alias:
        params["alias"] = alias

    try:
        response = requests.get(SHORT_JAMBO_ENDPOINT, params=params, timeout=10)
        response.raise_for_status()

        try:
            data = response.json()
            short_url = data.get("shortenedUrl") or response.text.strip()
        except Exception:
            short_url = response.text.strip()

        return {
            "success": True,
            "short_url": short_url,
            "long_url": long_url
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": str(e)
        }, 502

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", message="Forbidden"), 403

if __name__ == "__main__":
    app.run(debug=True)
