from flask import Flask, request, jsonify, render_template, abort, session
from datetime import datetime, timedelta
import uuid
import json
import os
import threading
import requests
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "replace_with_a_strong_secret")

# Storage files
KEYS_FILE = "/workspace/keys.json"
ACCESS_TOKENS_FILE = "/workspace/access_tokens.json"

# Make sure storage folder exists
os.makedirs("/workspace", exist_ok=True)

# Crypto key (keep secret!)
ENCRYPTION_KEY = os.getenv(
    "ENCRYPTION_KEY",
    "hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM=",
).encode()
cipher = Fernet(ENCRYPTION_KEY)

# Short Jambo API token (your token)
SHORT_JAMBO_API_TOKEN = os.getenv(
    "SHORT_JAMBO_API_TOKEN",
    "6e49817e3eab65f2f9b06f8c1319ba768a4ae9c4",
)
SHORT_JAMBO_ENDPOINT = "https://short-jambo.com/api"

# Admin key (always valid, no expiry, unlimited use)
ADMIN_KEY = os.getenv("ADMIN_KEY", "20102010")

# Simple in-process lock to avoid race conditions on file writes
_storage_lock = threading.Lock()


def _read_json_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_json_file(path: str, data: dict) -> None:
    with _storage_lock:
        with open(path, "w") as f:
            json.dump(data, f)


# Keys management

def load_keys() -> dict:
    return _read_json_file(KEYS_FILE)


def save_keys(keys: dict) -> None:
    _write_json_file(KEYS_FILE, keys)


# One-time access tokens for /genkey gating
# Structure: {
#   token: { "expires": iso8601, "used": bool, "generated_key": optional[str] }
# }

def load_access_tokens() -> dict:
    return _read_json_file(ACCESS_TOKENS_FILE)


def save_access_tokens(tokens: dict) -> None:
    _write_json_file(ACCESS_TOKENS_FILE, tokens)


def generate_unique_key(existing_keys: dict) -> str:
    while True:
        new_key = str(uuid.uuid4())
        if new_key not in existing_keys:
            return new_key


@app.route("/")
def index():
    return jsonify({
        "status": "ok",
        "endpoints": [
            "/create_genkey_link",
            "/genkey?access=<token>",
            "/verify?key=<encrypted_key>",
            "/adminkey (GET encrypted admin key)",
        ],
    })


@app.route("/create_genkey_link", methods=["POST", "GET"])
def create_genkey_link():
    """
    Creates a one-time access token and shortens a link to /genkey?access=<token>
    using the Short Jambo API. Returns the short URL.

    Optional query params:
      - alias: custom alias for the short link
      - ttl_minutes: integer minutes the access token is valid (default 10)
    """
    alias = request.args.get("alias")
    ttl_minutes_raw = request.args.get("ttl_minutes")
    try:
        ttl_minutes = int(ttl_minutes_raw) if ttl_minutes_raw else 10
    except ValueError:
        ttl_minutes = 10

    # Create a one-time access token
    access_tokens = load_access_tokens()
    token = str(uuid.uuid4())
    expiration_dt = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    access_tokens[token] = {
        "expires": expiration_dt.isoformat(),
        "used": False,
        "generated_key": None,
    }
    save_access_tokens(access_tokens)

    # Build the long URL to our /genkey endpoint
    base = request.url_root.rstrip("/")
    long_url = f"{base}/genkey?access={token}"

    # Call Short Jambo API to shorten
    params = {
        "api": SHORT_JAMBO_API_TOKEN,
        "url": long_url,
    }
    if alias:
        params["alias"] = alias

    try:
        resp = requests.get(SHORT_JAMBO_ENDPOINT, params=params, timeout=15)
        resp.raise_for_status()

        # API returns JSON, parse accordingly
        short_url = None
        try:
            data = resp.json()
            # The actual short URL is under "shortenedUrl" per your example
            short_url = data.get("shortenedUrl")
        except Exception:
            short_url = resp.text.strip()

        if not short_url:
            return jsonify({
                "success": False,
                "reason": "Unable to parse short link from API response",
                "raw_response": resp.text,
            }), 502

        return jsonify({
            "success": True,
            "short_url": short_url,
            "access_token": token,
            "expires": expiration_dt.isoformat(),
            "long_url": long_url,
        })
    except requests.RequestException as e:
        return jsonify({
            "success": False,
            "reason": "Shortening service error",
            "error": str(e),
        }), 502


@app.route("/genkey")
def generate_key():
    """
    Only accessible with a valid one-time access token via the shortened link.
    Generates a new encrypted key once per token. Refresh will not generate
    a new key again; subsequent loads will show an error.
    """
    access = request.args.get("access")
    if not access:
        return render_template("error.html", message="Access token missing"), 403

    access_tokens = load_access_tokens()
    token_info = access_tokens.get(access)

    if not token_info:
        return render_template("error.html", message="Invalid access token"), 403

    # Check expiry
    try:
        if datetime.fromisoformat(token_info["expires"]) < datetime.utcnow():
            return render_template("error.html", message="Access token expired"), 403
    except Exception:
        # Malformed date, reject
        return render_template("error.html", message="Access token invalid expiry"), 403

    # If already used, show error page - no regeneration allowed
    if token_info.get("used"):
        return render_template("error.html", message="This link was already used"), 403

    # Generate and store the new key
    keys = load_keys()
    new_key = generate_unique_key(keys)
    expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    keys[new_key] = {"expires": expiration, "used": False}
    save_keys(keys)

    # Mark token as used and bind the generated key to it
    token_info["used"] = True
    token_info["generated_key"] = new_key
    access_tokens[access] = token_info
    save_access_tokens(access_tokens)

    encrypted_key = cipher.encrypt(new_key.encode()).decode()
    return render_template("keygen.html", key=encrypted_key, expires=expiration)


@app.route("/verify")
def verify_key():
    provided_key = request.args.get("key")
    if not provided_key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    # Allow plaintext admin key directly
    if provided_key == ADMIN_KEY:
        return jsonify({"valid": True, "admin": True})

    # Try to decrypt; if decryption fails, still allow admin key check only
    decrypted_key = None
    try:
        decrypted_key = cipher.decrypt(provided_key.encode()).decode()
    except Exception:
        pass

    # If the decrypted value is the admin key, allow it as well
    if decrypted_key == ADMIN_KEY:
        return jsonify({"valid": True, "admin": True})

    if not decrypted_key:
        return jsonify({"valid": False, "reason": "Invalid encrypted key"}), 400

    keys = load_keys()
    key_info = keys.get(decrypted_key)

    if not key_info:
        return jsonify({"valid": False, "reason": "Key not found"}), 404

    if key_info.get("used"):
        return jsonify({"valid": False, "reason": "Key has already been used"}), 403

    if datetime.fromisoformat(key_info["expires"]) < datetime.utcnow():
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    keys[decrypted_key]["used"] = True
    save_keys(keys)

    return jsonify({"valid": True, "admin": False})


@app.route("/adminkey")
def get_admin_key():
    """Returns the encrypted admin key so it can be verified via /verify."""
    encrypted_admin_key = cipher.encrypt(ADMIN_KEY.encode()).decode()
    return jsonify({
        "encrypted_admin_key": encrypted_admin_key,
        "note": "This key is always valid and does not expire or get consumed.",
    })


# Minimal error page template rendering support
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", message="Forbidden"), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
