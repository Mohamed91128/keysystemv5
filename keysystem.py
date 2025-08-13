from flask import Flask, request, jsonify, render_template, session
from datetime import datetime, timedelta
import uuid
import json
import os
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "replace_with_a_long_random_secret_key"

KEYS_FILE = "keys.json"
USAGE_FILE = "usage.json"
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

def load_json(filename):
    return json.load(open(filename)) if os.path.exists(filename) else {}

def save_json(data, filename):
    json.dump(data, open(filename, "w"))

def get_user_id():
    if "user_id" not in session:
        session["user_id"] = str(uuid.uuid4())
    return session["user_id"]

def cleanup_usage(usage):
    today = datetime.now().strftime("%Y-%m-%d")
    for uid in list(usage.keys()):
        if usage[uid].get("date") != today:
            del usage[uid]

@app.route("/genkey")
def generate_key():
    uid = get_user_id()
    usage = load_json(USAGE_FILE)
    cleanup_usage(usage)

    user_data = usage.get(uid, {})
    if user_data.get("date") == datetime.now().strftime("%Y-%m-%d") and user_data.get("count", 0) >= 3:
        return render_template("error.html", message="You have reached the maximum of 3 keys per day."), 403

    raw_uuid = str(uuid.uuid4())
    encrypted = cipher.encrypt(raw_uuid.encode()).decode()
    expiration = (datetime.now() + timedelta(hours=24)).isoformat()

    keys = load_json(KEYS_FILE)
    keys[encrypted] = {"expires": expiration, "used": False}
    save_json(keys, KEYS_FILE)

    usage[uid] = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "count": user_data.get("count", 0) + 1
    }
    save_json(usage, USAGE_FILE)

    return render_template("keygen.html", key=encrypted, expires=expiration)

@app.route("/verify")
def verify_key():
    encrypted_key = request.args.get("key", "").replace(" ", "+")
    if not encrypted_key:
        return jsonify(valid=False, reason="No key provided"), 400

    keys = load_json(KEYS_FILE)
    key_info = keys.get(encrypted_key)
    if not key_info:
        return jsonify(valid=False, reason="Key not found"), 404

    if key_info["used"]:
        return jsonify(valid=False, reason="Key has already been used"), 403

    if datetime.fromisoformat(key_info["expires"]) < datetime.now():
        return jsonify(valid=False, reason="Key expired"), 403

    keys[encrypted_key]["used"] = True
    save_json(keys, KEYS_FILE)
    return jsonify(valid=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
