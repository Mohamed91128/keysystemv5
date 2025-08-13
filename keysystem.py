from flask import Flask, request, jsonify, render_template
from datetime import datetime, timedelta
import uuid
import json
import os
from cryptography.fernet import Fernet

app = Flask(__name__)

# File to store keys
KEYS_FILE = "keys.json"

# Use your existing Fernet key or generate a new one securely
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)


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


@app.route("/genkey")
def generate_key():
    keys = load_keys()

    # Optional: Clean up expired keys (older than 24h) here if you want

    new_key = generate_unique_key(keys)
    expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    keys[new_key] = {"expires": expiration, "used": False}
    save_keys(keys)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()

    # Return encrypted key and expiration in JSON
    # Or you can render a nice HTML page if you want
    return jsonify({
        "key": encrypted_key,
        "expires": expiration,
        "valid": True
    })


@app.route("/verify")
def verify_key():
    # Accept either 'key' or 'token' param (your client decides)
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


if __name__ == "__main__":
    # Run on 0.0.0.0 to be accessible externally (change port if needed)
    app.run(host="0.0.0.0", port=8080, debug=False)
