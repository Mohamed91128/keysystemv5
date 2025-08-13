from flask import Flask, request, jsonify, render_template, send_from_directory
from datetime import datetime, timedelta
import uuid
import json
import os
from cryptography.fernet import Fernet

app = Flask(__name__)

KEYS_FILE = "keys.json"
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

MAX_KEYS_PER_DAY = 4

def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)

def generate_unique_key(existing_keys):
    while True:
        new_key = str(uuid.uuid4())
        if new_key not in existing_keys:
            return new_key

def user_key_count_today(keys, user_ip):
    """Count how many keys generated today by user_ip"""
    today_str = datetime.utcnow().date().isoformat()
    count = 0
    for key, info in keys.items():
        if info.get("user_ip") == user_ip and info.get("created_date") == today_str:
            count += 1
    return count

@app.route("/genkey")
def generate_key():
    keys = load_keys()
    user_ip = request.remote_addr

    if user_key_count_today(keys, user_ip) >= MAX_KEYS_PER_DAY:
        # Render error page if limit exceeded
        return render_template("error.html", message=f"Limit reached: Max {MAX_KEYS_PER_DAY} keys per day."), 429

    new_key = generate_unique_key(keys)
    expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    created_date = datetime.utcnow().date().isoformat()

    # Save the key with user_ip and creation date
    keys[new_key] = {
        "expires": expiration,
        "used": False,
        "user_ip": user_ip,
        "created_date": created_date
    }
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()

    return render_template("keygen.html", key=encrypted_key, expires=expiration)

@app.route("/verify")
def verify_key():
    encrypted_key = request.args.get("key") or request.args.get("token")
    if not encrypted_key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    try:
        key = cipher.decrypt(encrypted_key.encode()).decode()
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid encrypted key"}), 400

    keys = load_keys()
    key_info = keys.get(key)

    if not key_info:
        return jsonify({"valid": False, "reason": "Key not found"}), 404

    if key_info.get("used"):
        return jsonify({"valid": False, "reason": "Key has already been used"}), 403

    if datetime.fromisoformat(key_info["expires"]) < datetime.utcnow():
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    # Mark key as used
    keys[key]["used"] = True
    save_keys(keys)

    return jsonify({"valid": True, "reason": "Token verified successfully"})

# Serve static files (space.js)
@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

if __name__ == "__main__":
    # debug=False in production
    app.run(host="0.0.0.0", port=8080, debug=True)
