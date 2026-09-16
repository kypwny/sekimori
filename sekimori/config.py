"""
Configuration loading and one-time provisioning.

Everything deployment-specific (homeserver name, panel URL, database
coordinates, the Synapse admin token, the WebUI password hash) lives in a
single JSON file, by default /etc/sekimori/config.json, mode 0640. Nothing
secret is ever stored in the source tree.

Override the path with $SEKIMORI_CONFIG.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys

DEFAULT_CONFIG_PATH = "/etc/sekimori/config.json"
ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

DEFAULTS = {
    # Where Synapse's client/federation listener is reachable.
    "synapse_url": "http://127.0.0.1:8008",
    # The homeserver name, i.e. the domain in @user:DOMAIN and !room:DOMAIN.
    "server_name": "example.com",
    # Public base URL of the homeserver, used to build registration links.
    "public_baseurl": "https://matrix.example.com",
    # A Synapse user with admin rights; its access token.
    "admin_token": "",
    "db": {
        "host": "localhost",
        "name": "synapse",
        "user": "synapse",
        "password": "",
    },
    "webui": {
        "host": "127.0.0.1",
        "port": 9099,
        "session_ttl": 43200,
    },
    "webui_password_hash": "",
    "secret_key": "",
}


def config_path(path=None):
    return path or os.environ.get("SEKIMORI_CONFIG") or DEFAULT_CONFIG_PATH


def _deep_merge(base, overlay):
    out = dict(base)
    for key, value in (overlay or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load(path=None):
    """Read the config, merged over DEFAULTS so missing keys never crash."""
    try:
        with open(config_path(path)) as handle:
            return _deep_merge(DEFAULTS, json.load(handle))
    except FileNotFoundError:
        return dict(DEFAULTS)
    except (OSError, ValueError):
        return dict(DEFAULTS)


def save(config, path=None):
    """Write the config with restrictive permissions."""
    target = config_path(path)
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")
    os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    return target


# --------------------------------------------------------------- passwords
def hash_password(password, n=2 ** 14, r=8, p=1):
    """scrypt hash, salted. Format: scrypt$N$r$p$salt_hex$hash_hex."""
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${derived.hex()}"


def verify_password(candidate, stored):
    """Constant-time check of a candidate against a stored scrypt hash."""
    if not stored or not candidate:
        return False
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        derived = hashlib.scrypt(
            candidate.encode(),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(hash_hex)),
        )
        return hmac.compare_digest(derived.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def gen_password(length=24):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def gen_secret():
    return secrets.token_hex(32)


def scraper_hint(path):
    """Best-effort: recover an admin token from a previously deployed client."""
    try:
        with open(path) as handle:
            import re
            match = re.search(
                r'os\.environ\.get\(\s*"ADMIN_TOKEN"\s*,\s*"([^"]+)"\s*\)', handle.read()
            )
            return match.group(1) if match else ""
    except OSError:
        return ""


# ------------------------------------------------------------------ setup
def setup(args):
    """Write (or update) the config file."""
    existing = load(args.config) if os.path.exists(config_path(args.config)) else {}

    password = None
    if args.rotate_password:
        stored_hash = existing.get("webui_password_hash") or ""
    elif args.password:
        password = args.password
        stored_hash = hash_password(password)
    elif existing.get("webui_password_hash"):
        stored_hash = existing["webui_password_hash"]
    else:
        password = gen_password()
        stored_hash = hash_password(password)

    db = dict(existing.get("db") or {})
    webui = dict(existing.get("webui") or {})
    for key, value in (
        ("host", args.db_host),
        ("name", args.db_name),
        ("user", args.db_user),
        ("password", args.db_password),
    ):
        if value is not None:
            db[key] = value
    if args.webui_host is not None:
        webui["host"] = args.webui_host
    if args.webui_port is not None:
        webui["port"] = args.webui_port

    config = _deep_merge(DEFAULTS, existing)
    config["db"] = _deep_merge(DEFAULTS["db"], db)
    config["webui"] = _deep_merge(DEFAULTS["webui"], webui)
    for key, value in (
        ("synapse_url", args.synapse_url),
        ("server_name", args.server_name),
        ("public_baseurl", args.public_baseurl),
        ("admin_token", args.admin_token),
    ):
        if value is not None:
            config[key] = value

    config["webui_password_hash"] = stored_hash
    config["secret_key"] = gen_secret()

    target = save(config, args.config)
    mode = oct(stat.S_IMODE(os.stat(target).st_mode))

    print(f"wrote {target} (mode {mode})")
    if not config.get("admin_token"):
        print("note: no admin_token set — the API calls will fail until you add one",
              file=sys.stderr)
    if not config["db"].get("password"):
        print("note: no db.password set — the census falls back to API-only stats",
              file=sys.stderr)
    if password:
        print(f"WEBUI_PASSWORD={password}")
    else:
        print("webui password unchanged")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sekimori-setup",
        description="Provision the sekimori config file.",
    )
    parser.add_argument("--config", default=None, help="config path (default /etc/sekimori/config.json)")
    parser.add_argument("--password", help="WebUI password (omit to generate one)")
    parser.add_argument("--rotate-password", action="store_true",
                        help="keep the existing password hash, refresh only the signing key")
    parser.add_argument("--synapse-url")
    parser.add_argument("--server-name")
    parser.add_argument("--public-baseurl")
    parser.add_argument("--admin-token")
    parser.add_argument("--db-host")
    parser.add_argument("--db-name")
    parser.add_argument("--db-user")
    parser.add_argument("--db-password")
    parser.add_argument("--webui-host")
    parser.add_argument("--webui-port", type=int)
    setup(parser.parse_args(argv))


if __name__ == "__main__":
    main()