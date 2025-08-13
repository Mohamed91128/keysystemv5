from flask import Flask, request, jsonify, render_template, session
from datetime import datetime, timedelta
import uuid
import json
import os
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "a_very_secret_key_change_this"  # Needed for Flask sessions

# Files
KEYS_FILE = "keys.json"
USAGE_FILE = "usage.json"

# Encryption Key
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

# ---------------- Helper Functions ---------------- #

def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, 'r') as f:
        return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f)

def load_usage():
    if not os.path.exists(USAGE_FILE):
        return {}
    with open(USAGE_FILE, 'r') as f:
        return json.load(f)

def save_usage(usage):
    with open(USAGE_FILE, 'w') as f:
        json.dump(usage, f)

def generate_unique_key(existing_keys):
    while True:
        new_key = str(uuid.uuid4())
        if new_key not in existing_keys:
            return new_key

def cleanup_usage(usage):
    today_str = datetime.now().strftime("%Y-%m-%d")
    keys_to_delete = [uid for uid, data in usage.items() if data.get("date") != today_str]
    for uid in keys_to_delete:
        del usage[uid]

def get_user_id():
    if "user_id" not in session:
        session["user_id"] = str(uuid.uuid4())
    return session["user_id"]

# ---------------- Routes ---------------- #

@app.route("/genkey")
def generate_key():
    user_id = get_user_id()
    today_str = datetime.now().strftime("%Y-%m-%d")

    usage = load_usage()
    cleanup_usage(usage)

    user_data = usage.get(user_id)
    if user_data and user_data.get("date") == today_str and user_data.get("count", 0) >= 3:
        return render_template("error.html", message="You have reached the maximum of 3 keys per day."), 403

    keys = load_keys()
    new_key = generate_unique_key(keys)
    expiration = (datetime.now() + timedelta(hours=24)).isoformat()

    keys[new_key] = {"expires": expiration, "used": False}
    save_keys(keys)

    if user_data and user_data.get("date") == today_str:
        usage[user_id]["count"] += 1
    else:
        usage[user_id] = {"date": today_str, "count": 1}
    save_usage(usage)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()
    return render_template("keygen.html", key=encrypted_key, expires=expiration)

@app.route("/verify")
def verify_key():
    encrypted_key = request.args.get("key")
    if not encrypted_key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    try:
        encrypted_key = encrypted_key.replace(" ", "+")
        key = cipher.decrypt(encrypted_key.encode()).decode()
    except Exception as e:
        return jsonify({"valid": False, "reason": f"Invalid encrypted key: {str(e)}"}), 400

    keys = load_keys()
    key_info = keys.get(key)

    if not key_info:
        return jsonify({"valid": False, "reason": "Key not found"}), 404

    if key_info.get("used"):
        return jsonify({"valid": False, "reason": "Key has already been used"}), 403

    if datetime.fromisoformat(key_info["expires"]) < datetime.now():
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    keys[key]["used"] = True
    save_keys(keys)

    return jsonify({"valid": True})

# ---------------- Run Server ---------------- #

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
