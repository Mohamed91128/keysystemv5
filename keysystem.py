from flask import Flask, request, jsonify, render_template
from datetime import datetime, timedelta
import uuid
import json
import os
from cryptography.fernet import Fernet

app = Flask(__name__)

KEYS_FILE = "keys.json"
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

def load_keys():
    if not os.path.exists(KEYS_FILE):
        # Structure with two top-level keys: keys and user_keys
        return {"keys": {}, "user_keys": {}}
    with open(KEYS_FILE, 'r') as f:
        return json.load(f)

def save_keys(data):
    with open(KEYS_FILE, 'w') as f:
        json.dump(data, f)

def generate_unique_key(existing_keys):
    while True:
        new_key = str(uuid.uuid4())
        if new_key not in existing_keys:
            return new_key

@app.route("/genkey")
def generate_key():
    user_ip = request.remote_addr
    today = datetime.now().strftime("%Y-%m-%d")

    data = load_keys()
    keys = data.get("keys", {})
    user_keys = data.get("user_keys", {})

    # How many keys has this user created today?
    user_day_count = user_keys.get(user_ip, {}).get(today, 0)

    if user_day_count >= 3:
        return jsonify({
            "error": "Daily key generation limit reached (3 per day)."
        }), 429

    new_key = generate_unique_key(keys)
    expiration = (datetime.now() + timedelta(hours=24)).isoformat()

    keys[new_key] = {
        "expires": expiration,
        "used": False,
        "owner": user_ip
    }

    # Update count for this user
    if user_ip not in user_keys:
        user_keys[user_ip] = {}
    user_keys[user_ip][today] = user_day_count + 1

    # Save everything back
    save_keys({"keys": keys, "user_keys": user_keys})

    encrypted_key = cipher.encrypt(new_key.encode()).decode()
    return render_template("keygen.html", key=encrypted_key, expires=expiration)

@app.route("/verify")
def verify_key():
    encrypted_key = request.args.get("key")
    if not encrypted_key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    try:
        key = cipher.decrypt(encrypted_key.encode()).decode()
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid encrypted key"}), 400

    data = load_keys()
    keys = data.get("keys", {})
    key_info = keys.get(key)

    if not key_info:
        return jsonify({"valid": False, "reason": "Key not found"}), 404

    if key_info.get("used"):
        return jsonify({"valid": False, "reason": "Key has already been used"}), 403

    if datetime.fromisoformat(key_info["expires"]) < datetime.now():
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    # Mark key as used
    keys[key]["used"] = True
    save_keys({"keys": keys, "user_keys": data.get("user_keys", {})})

    return jsonify({"valid": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
