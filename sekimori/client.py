"""
Synapse Admin API and database client.

The admin API is the primary interface. A handful of census numbers are
cheaper to read straight from Postgres, so those use `psql` when a database
password is configured and degrade to API-only stats when it is not.
"""
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from . import config as config_module

TIMEOUT = 30


class AdminClient:
    def __init__(self, config=None, config_path=None):
        self.config = config or config_module.load(config_path)
        self.base_url = (self.config.get("synapse_url") or "").rstrip("/")
        self.token = self.config.get("admin_token") or ""
        self.server_name = self.config.get("server_name") or ""
        db = self.config.get("db") or {}
        self.db_host = db.get("host") or "localhost"
        self.db_name = db.get("name") or "synapse"
        self.db_user = db.get("user") or "synapse"
        self.db_password = db.get("password") or ""

    # ------------------------------------------------------------ transport
    def request(self, method, path, body=None, params=None, timeout=TIMEOUT):
        url = f"{self.base_url}{path}"
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read().decode("utf-8")
                if not content.strip():
                    return {"status": "ok", "http_code": resp.status}
                return json.loads(content)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(raw)
                return {
                    "error": parsed.get("error", str(exc)),
                    "errcode": parsed.get("errcode", "UNKNOWN"),
                    "http_code": exc.code,
                }
            except ValueError:
                return {"error": raw or str(exc), "http_code": exc.code}
        except (urllib.error.URLError, OSError) as exc:
            return {"error": str(exc), "http_code": 0}

    # ---------------------------------------------------------- server info
    def server_version(self):
        return self.request("GET", "/_synapse/admin/v1/server_version")

    def client_versions(self):
        try:
            req = urllib.request.Request(f"{self.base_url}/_matrix/client/versions")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - surface any failure as data
            return {"error": str(exc), "versions": [], "unstable_features": {}}

    def capabilities(self):
        return self.request("GET", "/_matrix/client/v3/capabilities")

    # ---------------------------------------------------------------- users
    def list_users(self, from_token=None, limit=25, search_term=None,
                   deactivated=None, guests=None):
        params = {"limit": limit}
        if from_token:
            params["from"] = from_token
        if search_term:
            params["name"] = search_term
        if deactivated is not None:
            params["deactivated"] = str(deactivated).lower()
        if guests is not None:
            params["guests"] = str(guests).lower()
        return self.request("GET", "/_synapse/admin/v2/users", params=params)

    def get_user(self, user_id):
        return self.request("GET", f"/_synapse/admin/v2/users/{urllib.parse.quote(user_id)}")

    def upsert_user(self, user_id, displayname=None, password=None,
                    admin=None, deactivated=None):
        payload = {}
        if displayname is not None:
            payload["displayname"] = displayname
        if password is not None:
            payload["password"] = password
        if admin is not None:
            payload["admin"] = bool(admin)
        if deactivated is not None:
            payload["deactivated"] = bool(deactivated)
        return self.request(
            "PUT", f"/_synapse/admin/v2/users/{urllib.parse.quote(user_id)}", body=payload
        )

    def reset_password(self, user_id, new_password, logout_devices=False):
        return self.request(
            "POST",
            f"/_synapse/admin/v1/reset_password/{urllib.parse.quote(user_id)}",
            body={"new_password": new_password, "logout_devices": logout_devices},
        )

    def deactivate_user(self, user_id, erase=False):
        return self.request(
            "POST",
            f"/_synapse/admin/v1/deactivate/{urllib.parse.quote(user_id)}",
            body={"erase": erase},
        )

    def user_devices(self, user_id):
        return self.request(
            "GET", f"/_synapse/admin/v2/users/{urllib.parse.quote(user_id)}/devices"
        )

    def delete_user_device(self, user_id, device_id):
        return self.request(
            "DELETE",
            f"/_synapse/admin/v2/users/{urllib.parse.quote(user_id)}/devices/"
            f"{urllib.parse.quote(device_id)}",
        )

    def user_media(self, user_id, limit=50, from_token=None):
        params = {"limit": limit}
        if from_token:
            params["from"] = from_token
        return self.request(
            "GET",
            f"/_synapse/admin/v1/users/{urllib.parse.quote(user_id)}/media",
            params=params,
        )

    # ---------------------------------------------------------------- rooms
    def list_rooms(self, search_term=None, limit=25, from_offset=0,
                   order_by=None, direction=None):
        params = {"limit": limit, "from": from_offset}
        if search_term:
            params["search_term"] = search_term
        if order_by:
            params["order_by"] = order_by
        if direction:
            params["dir"] = direction
        return self.request("GET", "/_synapse/admin/v1/rooms", params=params)

    def get_room(self, room_id):
        return self.request("GET", f"/_synapse/admin/v1/rooms/{urllib.parse.quote(room_id)}")

    def room_members(self, room_id):
        return self.request(
            "GET", f"/_synapse/admin/v1/rooms/{urllib.parse.quote(room_id)}/members"
        )

    def room_state(self, room_id):
        return self.request(
            "GET", f"/_synapse/admin/v1/rooms/{urllib.parse.quote(room_id)}/state"
        )

    def room_extremities(self, room_id):
        return self.request(
            "GET",
            f"/_synapse/admin/v1/rooms/{urllib.parse.quote(room_id)}/forward_extremities",
        )

    def delete_room(self, room_id, new_room_user_id=None, room_name=None,
                    message=None, purge=False, block=False):
        payload = {"purge": purge, "block": block}
        if new_room_user_id:
            payload["new_room_user_id"] = new_room_user_id
        if room_name:
            payload["room_name"] = room_name
        if message:
            payload["message"] = message
        return self.request(
            "DELETE", f"/_synapse/admin/v2/rooms/{urllib.parse.quote(room_id)}", body=payload
        )

    def make_room_admin(self, room_id, user_id):
        return self.request(
            "POST",
            f"/_synapse/admin/v1/rooms/{urllib.parse.quote(room_id)}/make_room_admin",
            body={"user_id": user_id},
        )

    # --------------------------------------------------- registration tokens
    def list_tokens(self, valid=None):
        params = {}
        if valid is not None:
            params["valid"] = str(valid).lower()
        return self.request("GET", "/_synapse/admin/v1/registration_tokens", params=params)

    def create_token(self, token=None, uses_allowed=1, expiry_time=None, length=16):
        payload = {"uses_allowed": uses_allowed}
        if token:
            payload["token"] = token
        else:
            payload["length"] = length
        if expiry_time:
            payload["expiry_time"] = expiry_time
        return self.request(
            "POST", "/_synapse/admin/v1/registration_tokens/new", body=payload
        )

    def delete_token(self, token):
        return self.request(
            "DELETE", f"/_synapse/admin/v1/registration_tokens/{urllib.parse.quote(token)}"
        )

    def delete_all_tokens(self):
        """Delete every registration token. Returns (deleted, failed) lists."""
        listing = self.list_tokens()
        deleted, failed = [], []
        for entry in listing.get("registration_tokens", []):
            token = entry.get("token")
            result = self.delete_token(token)
            (failed if result.get("error") else deleted).append(token)
        return deleted, failed

    def registration_url(self, token):
        base = (self.config.get("public_baseurl") or "").rstrip("/")
        return f"{base}/#/register?token={urllib.parse.quote(token)}"

    # ----------------------------------------------------------- federation
    def list_destinations(self, limit=25, from_token=None, order_by=None, direction=None):
        params = {"limit": limit}
        if from_token:
            params["from"] = from_token
        if order_by:
            params["order_by"] = order_by
        if direction:
            params["dir"] = direction
        return self.request("GET", "/_synapse/admin/v1/federation/destinations", params=params)

    def get_destination(self, destination):
        return self.request(
            "GET",
            f"/_synapse/admin/v1/federation/destinations/{urllib.parse.quote(destination)}",
        )

    def reset_destination(self, destination):
        return self.request(
            "POST",
            f"/_synapse/admin/v1/federation/destinations/"
            f"{urllib.parse.quote(destination)}/reset_connection",
        )

    # ---------------------------------------------------------- media, misc
    def quarantine_media(self, server_name, media_id):
        return self.request(
            "POST", f"/_synapse/admin/v1/media/quarantine/{server_name}/{media_id}"
        )

    def quarantine_user_media(self, user_id):
        return self.request(
            "POST", f"/_synapse/admin/v1/user/{urllib.parse.quote(user_id)}/media/quarantine"
        )

    def unquarantine_user_media(self, user_id):
        return self.request(
            "POST", f"/_synapse/admin/v1/user/{urllib.parse.quote(user_id)}/media/unquarantine"
        )

    def purge_media_cache(self, before_ts_ms):
        return self.request(
            "POST", "/_synapse/admin/v1/purge_media_cache", params={"before_ts": before_ts_ms}
        )

    def media_statistics(self, limit=25, from_token=None, order_by=None, direction=None):
        params = {"limit": limit}
        if from_token:
            params["from"] = from_token
        if order_by:
            params["order_by"] = order_by
        if direction:
            params["dir"] = direction
        return self.request(
            "GET", "/_synapse/admin/v1/statistics/users/media", params=params
        )

    def event_reports(self, limit=25, from_token=None, direction=None):
        params = {"limit": limit}
        if from_token:
            params["from"] = from_token
        if direction:
            params["dir"] = direction
        return self.request("GET", "/_synapse/admin/v1/event_reports", params=params)

    def background_updates(self):
        return self.request("GET", "/_synapse/admin/v1/background_updates/status")

    # ------------------------------------------------------------- database
    def _psql(self, sql):
        """
        Run one read-only query via psql.

        Note: `psql -c` does NOT interpolate :variables — it hands the string
        to the server verbatim, so :'name' arrives as a syntax error. Nothing
        here needs interpolation: the queries are fixed strings with no
        caller-supplied values.
        """
        if not self.db_password:
            return {"error": "no db.password configured"}
        if not shutil.which("psql"):
            return {"error": "psql not found on PATH"}
        env = dict(os.environ, PGPASSWORD=self.db_password)
        cmd = ["psql", "-U", self.db_user, "-d", self.db_name, "-h", self.db_host, "-Atc", sql]
        try:
            result = subprocess.run(
                cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"error": str(exc)}
        if result.returncode != 0:
            return {"error": result.stderr.strip()}
        return {"result": result.stdout.strip()}

    def database_summary(self):
        """
        Cheap census. Row counts for the two huge tables come from the catalog
        estimate (reltuples) — an exact count(*) on `events` full-scans and
        blocks the panel for seconds on a multi-million-event server.

        Synapse's `users` table holds local accounts only (federated users are
        tracked elsewhere), so `count(*) FROM users` is already the local-user
        count. No config value is interpolated into any query here.
        """
        if not self.db_password:
            return {"error": "database not configured; using API-only stats"}

        summary = self._psql(
            """
            SELECT json_build_object(
                'total_events', (SELECT reltuples::bigint FROM pg_class WHERE relname = 'events'),
                'total_rooms', (SELECT count(*) FROM rooms),
                'total_users', (SELECT count(*) FROM users),
                'total_state_events', (SELECT reltuples::bigint FROM pg_class
                                       WHERE relname = 'current_state_events'),
                'total_access_tokens', (SELECT count(*) FROM access_tokens),
                'db_size', pg_size_pretty(pg_database_size(current_database()))
            );
            """
        )
        if "error" in summary:
            return summary
        try:
            return json.loads(summary["result"])
        except ValueError as exc:
            return {"error": str(exc), "raw": summary["result"]}

    def stats(self):
        """One call for everything the dashboard header needs."""
        return {
            "server_version": self.server_version(),
            "client_versions": self.client_versions(),
            "db": self.database_summary(),
            "server_name": self.server_name,
        }