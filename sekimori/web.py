"""
Bottle WebUI — the operator console.

Auth model: one shared password, scrypt-hashed in the config file. Sessions
are HMAC-signed cookies, HttpOnly + SameSite=Strict. Every route except
/login is gated, and non-GET requests are additionally checked against the
Origin header.
"""
import hashlib
import hmac
import json
import time

from bottle import HTTPResponse, Bottle, hook, request, response, run

from .client import AdminClient
from . import config as config_module

SESSION_COOKIE = "sekimori_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
OPEN_PATHS = {"/login", "/favicon.ico"}


def make_app(config=None, config_path=None):
    config = config or config_module.load(config_path)
    client = AdminClient(config=config)

    webui = config.get("webui") or {}
    session_ttl = int(webui.get("session_ttl") or 43200)
    server_name = config.get("server_name") or "homeserver"
    base_url = (config.get("public_baseurl") or "").rstrip("/")
    signing_key = (config.get("secret_key") or "").encode()
    password_hash = config.get("webui_password_hash") or ""

    # ip -> [failure_count, locked_until_epoch]
    attempts = {}

    app = Bottle()

    # ------------------------------------------------------------- sessions
    def make_session():
        expiry = int(time.time()) + session_ttl
        signature = hmac.new(signing_key, str(expiry).encode(), hashlib.sha256).hexdigest()
        return f"{expiry}.{signature}"

    def session_is_valid(token):
        if not token or "." not in token:
            return False
        expiry_str, signature = token.split(".", 1)
        try:
            expiry = int(expiry_str)
        except ValueError:
            return False
        if expiry < time.time():
            return False
        expected = hmac.new(signing_key, expiry_str.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def is_authed():
        return session_is_valid(request.get_cookie(SESSION_COOKIE))

    def set_session_cookie(token):
        response.set_cookie(
            SESSION_COOKIE, token, path="/", httponly=True, samesite="strict",
            max_age=session_ttl,
            secure=request.headers.get("X-Forwarded-Proto") == "https",
        )

    def client_ip():
        forwarded = request.headers.get("X-Forwarded-For")
        return (forwarded.split(",")[0].strip() if forwarded else request.remote_addr) or "?"

    def same_origin():
        origin = request.headers.get("Origin")
        if not origin:
            return True
        host = (request.headers.get("Host") or "").strip()
        return origin.split("://")[-1].rstrip("/") == host

    # ------------------------------------------------------------ auth gate
    def auth_gate():
        """
        Bottle discards before_request return values (App._handle calls
        trigger_hook, which keeps only exceptions), so aborting MUST be done
        by raising HTTPResponse. Returning a value would set the status but
        let the route still run — silently letting unauthenticated writes
        through.
        """
        path = request.path
        if path in OPEN_PATHS:
            return
        if not is_authed():
            if path.startswith("/api/"):
                raise HTTPResponse(
                    status=401,
                    body=json.dumps({"error": "unauthorized", "errcode": "M_UNAUTHORIZED"}),
                    headers={"Content-Type": "application/json"},
                )
            raise HTTPResponse(status=303, headers={"Location": "/login"}, body="")
        if request.method not in SAFE_METHODS and not same_origin():
            raise HTTPResponse(
                status=403,
                body=json.dumps({"error": "cross-origin request rejected",
                                 "errcode": "M_FORBIDDEN"}),
                headers={"Content-Type": "application/json"},
            )

    app.hook("before_request")(auth_gate)

    # ------------------------------------------------------------- rendering
    def render(template):
        return template.replace("{{SERVER_NAME}}", server_name)

    # --------------------------------------------------------------- routes
    @app.route("/")
    def index():
        response.set_header("Cache-Control", "no-store")
        return render(CONSOLE_PAGE)

    @app.route("/login", method="GET")
    def login_get():
        response.set_header("Cache-Control", "no-store")
        return render(LOGIN_PAGE.replace("{{MESSAGE}}", ""))

    @app.route("/login", method="POST")
    def login_post():
        response.set_header("Cache-Control", "no-store")
        ip = client_ip()
        now = time.time()
        record = attempts.get(ip)
        if record and record[1] > now:
            return render(LOGIN_PAGE.replace(
                "{{MESSAGE}}", f"Too many attempts. Try again in {int(record[1] - now)}s."
            ))
        if not password_hash:
            return render(LOGIN_PAGE.replace(
                "{{MESSAGE}}", "No WebUI password configured. Run sekimori-setup."
            ))
        if config_module.verify_password(request.forms.get("password") or "", password_hash):
            attempts.pop(ip, None)
            set_session_cookie(make_session())
            response.status = 303
            response.set_header("Location", "/")
            return ""
        count = (record[0] if record else 0) + 1
        locked_until = now + min(300, 2 ** min(count, 8)) if count >= 4 else 0
        attempts[ip] = [count, locked_until]
        time.sleep(0.5)
        return render(LOGIN_PAGE.replace("{{MESSAGE}}", "Incorrect password."))

    @app.route("/logout", method=("GET", "POST"))
    def logout():
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.status = 303
        response.set_header("Location", "/login")
        return ""

    # ------------------------------------------------------------------ api
    def as_json(payload):
        response.content_type = "application/json"
        return json.dumps(payload)

    @app.route("/api/dashboard")
    def api_dashboard():
        return as_json(client.stats())

    @app.route("/api/users")
    def api_users():
        return as_json(client.list_users(
            limit=int(request.query.get("limit", 50)),
            search_term=request.query.get("search") or None,
        ))

    @app.route("/api/users/<user_id:path>", method="GET")
    def api_user_get(user_id):
        return as_json(client.get_user(user_id))

    @app.route("/api/users/<user_id:path>", method="PUT")
    def api_user_put(user_id):
        data = request.json or {}
        return as_json(client.upsert_user(
            user_id,
            displayname=data.get("displayname"),
            password=data.get("password"),
            admin=data.get("admin"),
            deactivated=data.get("deactivated"),
        ))

    @app.route("/api/users/<user_id:path>/password", method="POST")
    def api_user_password(user_id):
        data = request.json or {}
        return as_json(client.reset_password(
            user_id, data.get("new_password", ""), data.get("logout_devices", False)
        ))

    @app.route("/api/users/<user_id:path>/deactivate", method="POST")
    def api_user_deactivate(user_id):
        data = request.json or {}
        return as_json(client.deactivate_user(user_id, erase=data.get("erase", False)))

    @app.route("/api/tokens")
    def api_tokens():
        return as_json(client.list_tokens())

    @app.route("/api/tokens", method="POST")
    def api_tokens_create():
        data = request.json or {}
        created = client.create_token(
            token=data.get("token"), uses_allowed=int(data.get("uses_allowed", 1))
        )
        if "token" in created:
            created["registration_url"] = client.registration_url(created["token"])
        return as_json(created)

    @app.route("/api/tokens/<token>", method="DELETE")
    def api_tokens_delete(token):
        if token == "__all__":
            deleted, failed = client.delete_all_tokens()
            return as_json({"deleted": deleted, "failed": failed})
        return as_json(client.delete_token(token))

    @app.route("/api/rooms")
    def api_rooms():
        return as_json(client.list_rooms(
            search_term=request.query.get("search") or None,
            limit=int(request.query.get("limit", 50)),
        ))

    @app.route("/api/rooms/<room_id:path>", method="GET")
    def api_room_get(room_id):
        return as_json(client.get_room(room_id))

    @app.route("/api/rooms/<room_id:path>/make_admin", method="POST")
    def api_room_make_admin(room_id):
        data = request.json or {}
        return as_json(client.make_room_admin(room_id, data.get("user_id")))

    @app.route("/api/rooms/<room_id:path>", method="DELETE")
    def api_room_delete(room_id):
        data = request.json or {}
        return as_json(client.delete_room(
            room_id, purge=data.get("purge", True), block=data.get("block", False)
        ))

    @app.route("/api/federation")
    def api_federation():
        return as_json(client.list_destinations(limit=int(request.query.get("limit", 50))))

    @app.route("/api/federation/<destination>/reset", method="POST")
    def api_federation_reset(destination):
        return as_json(client.reset_destination(destination))

    @app.route("/api/media/stats")
    def api_media_stats():
        return as_json(client.media_statistics(limit=int(request.query.get("limit", 25))))

    @app.route("/api/media/quarantine/user/<user_id:path>", method="POST")
    def api_media_quarantine(user_id):
        return as_json(client.quarantine_user_media(user_id))

    @app.route("/api/media/unquarantine/user/<user_id:path>", method="POST")
    def api_media_unquarantine(user_id):
        return as_json(client.unquarantine_user_media(user_id))

    @app.route("/api/media/quarantine_all", method="POST")
    def api_media_quarantine_all():
        stats = client.media_statistics(limit=1000)
        if "error" in stats:
            return as_json(stats)
        total, per_user = 0, {}
        for entry in stats.get("users", []):
            result = client.quarantine_user_media(entry["user_id"])
            count = result.get("num_quarantined", 0)
            per_user[entry["user_id"]] = count
            total += count
        return as_json({"num_quarantined": total, "by_user": per_user})

    @app.route("/api/media/purge_cache", method="POST")
    def api_media_purge_cache():
        import datetime as _datetime
        days = int(request.query.get("days", 30))
        now_ms = int(_datetime.datetime.now().timestamp() * 1000)
        return as_json(client.purge_media_cache(now_ms - days * 86400 * 1000))

    @app.route("/api/reports")
    def api_reports():
        return as_json(client.event_reports(limit=int(request.query.get("limit", 25))))

    return app, webui


LOGIN_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{SERVER_NAME}} — sign in</title>
<style>
:root{
  --bg:#0f1011; --panel:#151719; --line:#282b2f; --line-dark:#1d2024;
  --text:#dcd4c7; --dim:#7e776c; --faint:#47423b;
  --accent:#d69339; --accent-glow:rgba(214,147,57,0.18);
  --seal:#c43b2c; --seal-glow:rgba(196,59,44,0.22); --bad:#e05244;
  --mono:"Berkeley Mono","IBM Plex Mono","JetBrains Mono","SFMono-Regular","Cascadia Code",ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; background:var(--bg); color:var(--text); font-family:var(--mono);
  font-size:13px; display:flex; align-items:center; justify-content:center;
  background-image:
    radial-gradient(circle at center, transparent 35%, rgba(0,0,0,0.65) 100%),
    repeating-linear-gradient(0deg, rgba(255,255,255,0.015) 0 1px, transparent 1px 3px);
  text-shadow:0 0 1px rgba(220,212,199,0.35);
}
.card{
  border:1px solid var(--line); background:var(--panel); padding:28px 30px;
  width:min(440px,92vw); box-shadow:0 20px 50px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.04);
  position:relative;
}
.card::before{
  content:"関守"; position:absolute; top:16px; right:20px; font-size:22px;
  color:var(--faint); letter-spacing:0.2em; pointer-events:none; font-weight:700;
}
.sig{color:var(--accent);font-weight:700;letter-spacing:.02em;font-size:14px;text-shadow:0 0 10px var(--accent-glow)}
.sub{color:var(--dim);margin:4px 0 22px;font-size:12px}
label{display:block;color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
input{
  width:100%; background:var(--bg); border:1px solid var(--line); color:var(--text);
  padding:9px 10px; font-family:inherit; font-size:13px; outline:0;
  box-shadow:inset 0 2px 4px rgba(0,0,0,0.4);
}
input:focus{border-color:var(--accent);box-shadow:0 0 8px var(--accent-glow)}
button{
  margin-top:18px; width:100%; background:transparent; color:var(--accent);
  border:1px solid var(--accent); padding:9px 10px; font-family:inherit;
  font-size:13px; cursor:pointer; letter-spacing:0.04em;
  transition:all 0.15s ease;
}
button:hover{background:rgba(214,147,57,0.12);box-shadow:0 0 12px var(--accent-glow)}
.msg{color:var(--bad);margin-top:14px;min-height:1em}
.note{color:var(--faint);margin-top:20px;font-size:11px;line-height:1.6}
</style>
</head>
<body>
<form class="card" method="post" action="/login">
  <div class="sig">{{SERVER_NAME}}</div>
  <div class="sub">checkpoint keeper — sign in required</div>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
  <button type="submit">sign in</button>
  <div class="msg">{{MESSAGE}}</div>
  <div class="note">Sessions last 12 hours by default. Failed attempts are rate-limited per IP.</div>
</form>
</body>
</html>
"""


CONSOLE_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{SERVER_NAME}} — operator console</title>
<style>
:root{
  --bg:#0f1011;
  --panel:#151719;
  --panel-alt:#1a1c1f;
  --line:#282b2f;
  --line-faint:#1d2024;
  --text:#dcd4c7;
  --dim:#7e776c;
  --faint:#47423b;
  --accent:#d69339;
  --accent-dim:#8b5e20;
  --accent-glow:rgba(214,147,57,0.18);
  --seal:#c43b2c;
  --seal-dim:#5a1f18;
  --seal-glow:rgba(196,59,44,0.25);
  --ok:#6fa975;
  --bad:#e05244;
  --warn:#d69339;
  --info:#6ea5c9;
  --mono:"Berkeley Mono","IBM Plex Mono","JetBrains Mono","SFMono-Regular","Cascadia Code",ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;
  background-color:var(--bg);
  background-image:
    radial-gradient(circle at center, transparent 35%, rgba(0,0,0,0.6) 100%),
    repeating-linear-gradient(0deg, rgba(255,255,255,0.012) 0 1px, transparent 1px 3px);
  color:var(--text);
  font-family:var(--mono);
  font-size:13px;
  line-height:1.45;
  overflow:hidden;
  text-shadow:0 0 1px rgba(220,212,199,0.35);
}
a{color:var(--info);text-decoration:none}
a:hover{text-decoration:underline}
button,input{font:inherit}
#console{height:100vh;display:grid;grid-template-rows:auto 1fr auto;position:relative}
#console::before{
  content:"";
  position:absolute;
  inset:0;
  pointer-events:none;
  background:radial-gradient(ellipse at 50% 15%, transparent 60%, rgba(0,0,0,0.4) 100%);
  z-index:10;
}
#topline{
  border-bottom:1px solid var(--line);
  background:var(--panel);
  padding:8px 14px;
  display:flex;
  align-items:center;
  gap:14px;
  white-space:nowrap;
  overflow:hidden;
  box-shadow:0 2px 8px rgba(0,0,0,0.5);
  z-index:2;
}
.sig{color:var(--accent);font-weight:700;letter-spacing:.04em;text-shadow:0 0 8px var(--accent-glow)}
.meta{color:var(--dim)}
.meta b{color:var(--text);font-weight:500}
.dot{color:var(--faint)}
#clock{margin-left:auto;color:var(--dim)}
#latency{color:var(--dim)}
#lock{
  color:var(--dim);
  text-decoration:none;
  border:1px solid var(--line);
  padding:2px 8px;
  letter-spacing:0.04em;
  font-size:12px;
  transition:all 0.15s ease;
}
#lock:hover{color:var(--accent);border-color:var(--accent);box-shadow:0 0 6px var(--accent-glow);text-decoration:none}
#scrollback{
  overflow-y:auto;
  padding:18px 16px 26px;
  scrollbar-width:thin;
  scrollbar-color:var(--faint) transparent;
  z-index:1;
}
.line{max-width:1180px;margin:0 auto}
.entry{margin:0 0 14px}
.cmdline{color:var(--accent);user-select:none;cursor:pointer;letter-spacing:0.02em}
.cmdline:hover{color:#f0b25e;text-shadow:0 0 6px var(--accent-glow)}
.out{margin:4px 0 0;color:var(--text);white-space:pre-wrap;overflow-wrap:anywhere}
.out .dim{color:var(--dim)}
.out .ok{color:var(--ok)}
.out .bad{color:var(--bad)}
.out .warn{color:var(--warn)}
.out .info{color:var(--info)}
.banner{
  color:var(--dim);
  font-size:11px;
  line-height:1.2;
  margin-bottom:12px;
  user-select:none;
  text-shadow:0 0 4px var(--accent-glow);
}
.banner b{color:var(--accent)}
.table{display:table;border-collapse:collapse;margin:6px 0 2px;max-width:100%}
.tr{display:table-row}
.th,.td{display:table-cell;padding:3px 14px 3px 0;border-bottom:1px solid var(--line-faint);vertical-align:top}
.th{color:var(--dim);text-transform:uppercase;font-size:11px;letter-spacing:.08em}
.td{white-space:pre-wrap;overflow-wrap:anywhere}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}
.btn{
  background:transparent;
  color:var(--text);
  border:1px solid var(--line);
  border-radius:0;
  padding:3px 9px;
  cursor:pointer;
  font-family:inherit;
  font-size:12px;
  transition:all 0.15s ease;
}
.btn:hover{border-color:var(--accent-dim);color:var(--accent);box-shadow:0 0 6px var(--accent-glow)}
.btn.danger{
  color:var(--seal);
  border:1px solid var(--seal-dim);
}
.btn.danger:hover{
  border-color:var(--seal);
  color:#ff8575;
  box-shadow:0 0 8px var(--seal-glow);
}
.btn.ok{color:var(--ok);border-color:#2a442e}
.btn.ok:hover{border-color:var(--ok);box-shadow:0 0 6px rgba(111,169,117,0.25)}

/* Stamp (捺印) & Tegata (通行手形) motif */
.stamp{
  display:inline-flex;
  align-items:center;
  gap:6px;
  border:2px double var(--seal);
  padding:4px 10px;
  color:var(--seal);
  background:rgba(196,59,44,0.06);
  font-size:12px;
  letter-spacing:0.06em;
  font-weight:700;
  text-shadow:0 0 8px var(--seal-glow);
  box-shadow:inset 0 0 6px var(--seal-glow);
  margin-top:4px;
}
.btn.seal{
  border:2px double var(--seal);
  background:rgba(196,59,44,0.08);
  color:var(--seal);
  font-weight:700;
  letter-spacing:0.06em;
  padding:4px 12px;
  text-shadow:0 0 8px var(--seal-glow);
  box-shadow:inset 0 0 8px var(--seal-glow);
}
.btn.seal:hover{
  background:rgba(196,59,44,0.2);
  color:#ffa296;
  border-color:#e05244;
  box-shadow:0 0 12px var(--seal-glow), inset 0 0 10px var(--seal-glow);
}

.tegata-box{
  border:1px solid var(--line);
  background:var(--panel);
  padding:12px 16px;
  margin:6px 0;
  max-width:620px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,0.03), 0 4px 12px rgba(0,0,0,0.4);
  position:relative;
}
.tegata-head{
  display:flex;
  justify-content:space-between;
  align-items:center;
  border-bottom:1px solid var(--line-faint);
  padding-bottom:8px;
  margin-bottom:10px;
}
.tegata-title{
  color:var(--accent);
  font-weight:700;
  letter-spacing:0.08em;
  font-size:12px;
}
.tegata-seal{
  color:var(--seal);
  font-weight:700;
  border:1px solid var(--seal-dim);
  padding:1px 6px;
  font-size:11px;
  letter-spacing:0.1em;
}
.tegata-field{
  display:flex;
  gap:12px;
  margin:4px 0;
  font-size:12px;
}
.tegata-k{color:var(--dim);min-width:70px;text-transform:uppercase;font-size:11px;letter-spacing:0.06em}
.tegata-v{color:var(--text);word-break:break-all}

#prompt{
  border-top:1px solid var(--line);
  background:var(--panel);
  display:flex;
  align-items:center;
  gap:10px;
  padding:10px 14px;
  box-shadow:0 -2px 10px rgba(0,0,0,0.4);
  z-index:2;
}
#ps1{color:var(--accent);white-space:nowrap;user-select:none;text-shadow:0 0 8px var(--accent-glow);font-weight:700}
#input{
  flex:1;
  background:transparent;
  border:0;
  outline:0;
  color:var(--text);
  caret-color:var(--accent);
  text-shadow:0 0 2px rgba(220,212,199,0.3);
}
#input::placeholder{color:var(--faint)}
#hint{color:var(--faint);font-size:11px;white-space:nowrap}
.cursor{
  display:inline-block;
  width:.62em;
  height:1.05em;
  background:var(--accent);
  vertical-align:-.16em;
  animation:blink 1s steps(1) infinite;
  box-shadow:0 0 6px var(--accent-glow);
}
@keyframes blink{50%{opacity:0}}
@media (prefers-reduced-motion: reduce){.cursor{animation:none}}
@media (max-width:760px){
  body{font-size:12px}
  #topline{gap:8px;overflow-x:auto}
  #hint{display:none}
  #scrollback{padding:14px 10px 22px}
}
#palette{
  display:none;
  position:fixed;
  left:50%;top:18%;
  transform:translateX(-50%);
  width:min(580px,92vw);
  background:var(--panel);
  border:1px solid var(--line);
  box-shadow:0 18px 48px rgba(0,0,0,0.7), 0 0 20px rgba(0,0,0,0.5);
  z-index:50;
}
#palette.open{display:block}
#palette-input{
  width:100%;
  background:transparent;
  border:0;
  border-bottom:1px solid var(--line);
  outline:0;
  color:var(--text);
  padding:12px 14px;
  font-family:inherit;
  font-size:13px;
  box-shadow:inset 0 1px 4px rgba(0,0,0,0.3);
}
#palette-list{max-height:340px;overflow-y:auto}
.palette-item{
  padding:9px 14px;
  cursor:pointer;
  display:flex;
  gap:12px;
  align-items:baseline;
  border-bottom:1px solid rgba(40,43,47,0.5);
  transition:background 0.1s ease;
}
.palette-item:last-child{border-bottom:0}
.palette-item .k{color:var(--accent);min-width:180px}
.palette-item .d{color:var(--dim);font-size:12px}
.palette-item.active{background:rgba(214,147,57,0.12)}
#cheatsheet{margin-top:6px;color:var(--faint);font-size:12px;line-height:1.7}
#cheatsheet b{color:var(--dim);font-weight:500}
.form-block{
  border:1px solid var(--line);
  background:var(--panel);
  padding:14px;
  margin-top:6px;
  max-width:540px;
  box-shadow:0 4px 12px rgba(0,0,0,0.4);
}
.form-block label{display:block;color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin:8px 0 3px}
.form-block input{
  width:100%;
  background:var(--bg);
  border:1px solid var(--line);
  color:var(--text);
  padding:6px 8px;
  font-family:inherit;
  font-size:13px;
  outline:0;
}
.form-block input:focus{border-color:var(--accent);box-shadow:0 0 6px var(--accent-glow)}
.form-block .row{display:flex;gap:8px;margin-top:12px}
</style>
</head>
<body>
<div id="console">
  <div id="topline" aria-label="server status">
    <span class="sig">{{SERVER_NAME}}</span>
    <span class="meta">synapse <b id="synapse-version">…</b></span>
    <span class="dot">·</span>
    <span class="meta">client <b id="client-versions">…</b></span>
    <span class="dot">·</span>
    <span class="meta">db <b id="db-size">…</b></span>
    <span class="dot">·</span>
    <span class="meta">events <b id="event-count">…</b></span>
    <span id="clock">--:--:--Z</span>
    <span id="latency">· ms</span>
    <a id="lock" href="/logout" title="end this admin session">lock</a>
  </div>

  <div id="scrollback">
    <div class="line">
      <div class="entry">
        <div class="out">
<div class="banner">
  ███████╗███████╗██╗  ██╗██╗███╗   ███╗ ██████╗ ██████╗ ██╗
  ██╔════╝██╔════╝██║ ██╔╝██║████╗ ████║██╔═══██╗██╔══██╗██║
  ███████╗█████╗  █████╔╝ ██║██╔████╔██║██║   ██║██████╔╝██║
  ╚════██║██╔══╝  ██╔═██╗ ██║██║╚██╔╝██║██║   ██║██╔══██╗██║
  ███████║███████╗██║  ██╗██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝
  <b>関守</b> · checkpoint keeper for matrix homeservers
</div>
<span class="ok">sekimori online.</span> <span class="dim">Type <b style="color:var(--accent)">help</b> or press <b style="color:var(--accent)">ctrl-k</b> for the command palette.</span>

<span class="dim">most used:</span>
  status · users · tokens · rooms · fed · media · reports
        </div>
      </div>
    </div>
  </div>

  <form id="prompt" autocomplete="off">
    <span id="ps1">sekimori:/ $</span>
    <input id="input" name="command" spellcheck="false" autocomplete="off" placeholder="type a command — / to focus, ctrl-k for palette" aria-label="admin command">
    <span class="cursor" aria-hidden="true"></span>
    <span id="hint">ctrl-k palette · enter run</span>
  </form>
</div>

<div id="palette" role="dialog" aria-label="command palette">
  <input id="palette-input" placeholder="filter commands…" autocomplete="off" spellcheck="false">
  <div id="palette-list"></div>
</div>

<script>
const SERVER_NAME = "{{SERVER_NAME}}";
const $ = (id) => document.getElementById(id);
const scrollback = $("scrollback");
const lineRoot = scrollback.querySelector(".line");
const input = $("input");
const palette = $("palette");
const paletteInput = $("palette-input");
const paletteList = $("palette-list");
const history = [];
let historyIndex = -1;

const COMMANDS = [
  {cmd:"status", desc:"server census — versions, db size, event counts"},
  {cmd:"users", desc:"list users", run:"users"},
  {cmd:"users <query>", desc:"search users by name/id", run:"users "},
  {cmd:"user new", desc:"create a user (guided form)", form:"userNew"},
  {cmd:"user passwd <@id:server> <pw>", desc:"reset a user's password", run:"user passwd "},
  {cmd:"user admin <@id:server>", desc:"grant server admin", run:"user admin "},
  {cmd:"user deactivate <@id:server>", desc:"deactivate (asks to confirm)", run:"user deactivate "},
  {cmd:"tokens", desc:"list registration tokens", run:"tokens"},
  {cmd:"token new", desc:"mint a registration token (guided)", form:"tokenNew"},
  {cmd:"token del <token>", desc:"delete a registration token", run:"token del "},
  {cmd:"token del --all", desc:"delete EVERY registration token", run:"token del --all"},
  {cmd:"rooms", desc:"list rooms by size", run:"rooms"},
  {cmd:"rooms <query>", desc:"search rooms by name", run:"rooms "},
  {cmd:"room get <!room:id>", desc:"raw room record", run:"room get "},
  {cmd:"room members <!room:id>", desc:"list room members", run:"room members "},
  {cmd:"room admin <room> <user>", desc:"promote user in room", run:"room admin "},
  {cmd:"room purge <!room:id>", desc:"purge room (asks to confirm)", run:"room purge "},
  {cmd:"fed", desc:"federation destinations", run:"fed"},
  {cmd:"fed reset <host>", desc:"unstick federation retry", run:"fed reset "},
  {cmd:"media", desc:"top media storage users", run:"media"},
  {cmd:"media purge-cache 30", desc:"purge remote media cache >30d", run:"media purge-cache 30"},
  {cmd:"media quarantine <@user>", desc:"quarantine a user's media", run:"media quarantine "},
  {cmd:"media unquarantine <@user>", desc:"restore a user's quarantined media", run:"media unquarantine "},
  {cmd:"media quarantine --all", desc:"quarantine EVERY user's media", run:"media quarantine --all"},
  {cmd:"reports", desc:"abuse reports", run:"reports"},
  {cmd:"help", desc:"full reference", run:"help"},
  {cmd:"logout", desc:"end this admin session", run:"logout"},
  {cmd:"clear", desc:"clear scrollback (ctrl-l)", run:"clear"},
];

function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function fmtTs(ts){
  if(!ts) return "-";
  if(ts > 1e11) ts = ts / 1000;
  return new Date(ts * 1000).toISOString().replace("T"," ").slice(0,19) + "Z";
}
function fmtBytes(n){
  n = Number(n || 0);
  const units = ["B","KB","MB","GB","TB"];
  let i = 0;
  while(n >= 1024 && i < units.length - 1){ n /= 1024; i++; }
  return `${n.toFixed(i ? 2 : 0)} ${units[i]}`;
}
function printCmd(cmd){
  const div = document.createElement("div");
  div.className = "entry";
  div.innerHTML = `<div class="cmdline" title="click to re-run">sekimori:/ $ ${esc(cmd)}</div>`;
  div.querySelector(".cmdline").addEventListener("click", () => run(cmd));
  lineRoot.appendChild(div);
  return div;
}
function printOut(entry, html){
  const out = document.createElement("div");
  out.className = "out";
  out.innerHTML = html;
  entry.appendChild(out);
  scrollback.scrollTop = scrollback.scrollHeight;
}
function printError(entry, msg){
  printOut(entry, `<span class="bad">error</span> <span class="dim">${esc(msg)}</span> <span class="dim">— try help or ctrl-k</span>`);
}
async function api(path, options){
  const t0 = performance.now();
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  $("latency").textContent = `${Math.max(1, Math.round(performance.now() - t0))} ms`;
  if(res.status === 401){ location.href = "/login"; return {}; }
  if(!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  if(data.error && !data.errcode) throw new Error(data.error);
  return data;
}
function table(headers, rows){
  const head = headers.map(h => `<span class="th">${esc(h)}</span>`).join("");
  const body = rows.map(r => `<span class="tr">${r.map(c => `<span class="td">${c}</span>`).join("")}</span>`).join("");
  return `<span class="table"><span class="tr">${head}</span>${body}</span>`;
}
function badge(text, cls){ return `<span class="${cls}">${esc(text)}</span>`; }
function actions(buttons){
  return `<span class="actions">${buttons.map(b => `<button class="btn ${b.cls || ""}" data-cmd="${esc(b.cmd)}">${esc(b.label)}</button>`).join("")}</span>`;
}
async function refreshHeader(){
  try{
    const d = await api("/api/dashboard");
    $("synapse-version").textContent = d.server_version?.server_version || "?";
    const versions = d.client_versions?.versions || [];
    $("client-versions").textContent = versions.slice(-2).join(" / ") || "?";
    $("db-size").textContent = d.db?.db_size || "n/a";
    $("event-count").textContent = Number(d.db?.total_events || 0).toLocaleString();
  }catch(e){
    $("latency").textContent = "offline";
  }
}
function tickClock(){ $("clock").textContent = new Date().toISOString().slice(11,19) + "Z"; }
setInterval(tickClock, 1000);
tickClock();

const handlers = {
  async status(entry){
    const d = await api("/api/dashboard");
    const db = d.db || {};
    printOut(entry, table(["key","value"], [
      ["homeserver", esc(d.server_name || "-")],
      ["synapse", esc(d.server_version?.server_version || "?")],
      ["client api versions", esc((d.client_versions?.versions || []).slice(-6).join(", "))],
      ["msc features", esc(Object.keys(d.client_versions?.unstable_features || {}).length)],
      ["database size", esc(db.db_size || "unavailable")],
      ["events (estimate)", esc(Number(db.total_events || 0).toLocaleString())],
      ["rooms", esc(db.total_rooms ?? "?")],
      ["users (local)", esc(db.total_users ?? "?")],
      ["state events (estimate)", esc(Number(db.total_state_events || 0).toLocaleString())],
      ["access tokens", esc(db.total_access_tokens ?? "?")]
    ]) + actions([
      {label:"users",cmd:"users"},{label:"rooms",cmd:"rooms"},
      {label:"fed",cmd:"fed"},{label:"media",cmd:"media"}
    ]));
  },
  async users(entry, args){
    const q = args.join(" ");
    const d = await api("/api/users" + (q ? `?search=${encodeURIComponent(q)}` : ""));
    const rows = (d.users || []).map(u => [
      `<b>${esc(u.name)}</b>`,
      esc(u.displayname || "-"),
      u.admin ? badge("admin","info") : "user",
      u.deactivated ? badge("deactivated","bad") : (u.locked ? badge("locked","warn") : badge("active","ok")),
      esc(fmtTs(u.last_seen_ts))
    ]);
    printOut(entry, (rows.length ? table(["user","display","role","state","last seen"], rows) : `<span class="dim">no users</span>`) +
      `<span class="dim"> total ${esc(d.total ?? rows.length)}</span>` +
      actions([{label:"+ new user",cmd:"user new"},{label:"tokens",cmd:"tokens"},{label:"reports",cmd:"reports"}]));
  },
  async user(entry, args){
    const id = args[0];
    if(!id) return printError(entry, "usage: user <@id:server> — or: user new / user passwd / user admin / user deactivate");
    const d = await api(`/api/users/${encodeURIComponent(id)}`);
    printOut(entry, `<span class="dim">raw user object</span>\n${esc(JSON.stringify(d, null, 2))}`);
  },
  async "user new"(entry, args){
    const id = args[0];
    if(!id) return printError(entry, "usage: user new <@id:server> [password] [display name] — or use the palette (ctrl-k)");
    if(!id.startsWith("@") || !id.includes(":")) return printError(entry, "user id must look like @name:server");
    const password = args[1] || "";
    const displayname = args.slice(2).join(" ") || id.split(":")[0].slice(1);
    const d = await api(`/api/users/${encodeURIComponent(id)}`, {method:"PUT", headers:{"Content-Type":"application/json"}, body:JSON.stringify({password, displayname, admin:false})});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("created","ok")} <b>${esc(id)}</b> <span class="dim">(${esc(displayname)})</span>${password ? "" : `\n<span class="warn">no password set</span> — <button class="btn" data-cmd="user passwd ${esc(id)} ">set one now</button>`}`);
  },
  async "user passwd"(entry, args){
    const [id, ...pw] = args;
    if(!id || !pw.length) return printError(entry, "usage: user passwd <@id:server> <new password>");
    const d = await api(`/api/users/${encodeURIComponent(id)}/password`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({new_password: pw.join(" "), logout_devices:false})});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("password reset","ok")} ${esc(id)}`);
  },
  async "user deactivate"(entry, args){
    const id = args[0];
    if(!id) return printError(entry, "usage: user deactivate <@id:server>");
    printOut(entry, `<div class="stamp">【 捺印待機 : DEACTIVATION ARMED 】</div>\n` +
      `<span class="dim">Destructive action against account:</span> <b>${esc(id)}</b>\n` +
      actions([{label:`捺印確認: DEACTIVATE ${id}`,cmd:`confirm deactivate ${id}`,cls:"seal"}]));
    handlers[`confirm deactivate ${id}`] = async (e2) => {
      const d = await api(`/api/users/${encodeURIComponent(id)}/deactivate`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({erase:false})});
      if(d.error) return printError(e2, d.error);
      printOut(e2, `<div class="stamp">【 執行済 : ACCOUNT DEACTIVATED 】</div> <b>${esc(id)}</b>`);
      delete handlers[`confirm deactivate ${id}`];
    };
  },
  async "user admin"(entry, args){
    const id = args[0];
    if(!id) return printError(entry, "usage: user admin <@id:server>");
    const d = await api(`/api/users/${encodeURIComponent(id)}`, {method:"PUT", headers:{"Content-Type":"application/json"}, body:JSON.stringify({admin:true})});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("admin granted","ok")} ${esc(id)}`);
  },
  async tokens(entry){
    const d = await api("/api/tokens");
    const rows = (d.registration_tokens || []).map(t => [
      `<b>${esc(t.token)}</b>`,
      esc(t.uses_allowed ?? "unlimited"),
      esc(t.completed ?? 0),
      esc(t.pending ?? 0),
      esc(fmtTs(t.expiry_time))
    ]);
    printOut(entry, (rows.length ? table(["token","uses","done","pending","expires"], rows) : `<span class="dim">no tokens</span>`) +
      actions([
        {label:"token new 1",cmd:"token new 1"},
        {label:"token new 15",cmd:"token new 15"},
        {label:"delete ALL",cmd:"token del --all",cls:"danger"}
      ]));
  },
  async "token new"(entry, args){
    const uses = parseInt(args[0] || "1", 10);
    const d = await api("/api/tokens", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({uses_allowed: uses})});
    if(d.error) return printError(entry, d.error);
    const link = d.registration_url || "";
    printOut(entry, `
<div class="tegata-box">
  <div class="tegata-head">
    <span class="tegata-title">関守 · 通行手形 (REGISTRATION PASS)</span>
    <span class="tegata-seal">認 (APPROVED)</span>
  </div>
  <div class="tegata-field">
    <span class="tegata-k">TOKEN:</span>
    <span class="tegata-v"><b>${esc(d.token)}</b></span>
  </div>
  <div class="tegata-field">
    <span class="tegata-k">ENTRIES:</span>
    <span class="tegata-v">${uses} use${uses > 1 ? "s" : ""}</span>
  </div>
  <div class="tegata-field">
    <span class="tegata-k">REGISTER:</span>
    <span class="tegata-v"><a href="#" data-copy="${esc(link)}">${esc(link)}</a> <span class="dim">(click to copy)</span></span>
  </div>
</div>`);
  },
  async "token del"(entry, args){
    const token = args[0];
    if(!token) return printError(entry, "usage: token del <token> — or token del --all");
    if(token === "--all"){
      printOut(entry, `<div class="stamp">【 捺印待機 : PURGE ALL TOKENS 】</div>\n` +
        `<span class="dim">Revoke every active registration token</span>\n` +
        actions([{label:"捺印確認: REVOKE ALL TOKENS",cmd:"confirm token del --all",cls:"seal"}]));
      handlers["confirm token del --all"] = async (e2) => {
        const d = await api("/api/tokens/__all__", {method:"DELETE"});
        if(d.error) return printError(e2, d.error);
        printOut(e2, `<div class="stamp">【 執行済 : ALL TOKENS REVOKED 】</div> ${esc(d.deleted?.length ?? 0)} removed${d.failed?.length ? `, ${d.failed.length} failed` : ""}`);
        delete handlers["confirm token del --all"];
      };
      return;
    }
    const d = await api(`/api/tokens/${encodeURIComponent(token)}`, {method:"DELETE"});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("deleted","ok")} ${esc(token)}`);
  },
  async rooms(entry, args){
    const q = args.join(" ");
    const d = await api("/api/rooms" + (q ? `?search=${encodeURIComponent(q)}` : ""));
    const rows = (d.rooms || []).map(r => [
      esc((r.room_id || "").slice(0, 18) + "…"),
      `<b>${esc(r.name || "unnamed")}</b>`,
      esc(r.joined_members ?? 0),
      esc(r.joined_local_members ?? 0),
      `v${esc(r.version ?? "?")}`,
      r.encryption ? badge("e2ee","ok") : "clear",
      esc(r.state_events ?? 0)
    ]);
    printOut(entry, (rows.length ? table(["room","name","members","local","ver","crypto","state"], rows) : `<span class="dim">no rooms</span>`) +
      `<span class="dim"> total ${esc(d.total_rooms ?? rows.length)}</span>` +
      actions([{label:"search rooms",cmd:"rooms "},{label:"biggest rooms",cmd:"rooms"},{label:"fed",cmd:"fed"}]));
  },
  async "room get"(entry, args){
    const id = args[0];
    if(!id) return printError(entry, "usage: room get <!room:id>");
    const d = await api(`/api/rooms/${encodeURIComponent(id)}`);
    printOut(entry, `<span class="dim">raw room object</span>\n${esc(JSON.stringify(d, null, 2))}`);
  },
  async "room members"(entry, args){
    const id = args[0];
    if(!id) return printError(entry, "usage: room members <!room:id>");
    const d = await api(`/api/rooms/${encodeURIComponent(id)}/members`);
    if(d.error) return printError(entry, d.error);
    const members = d.members || [];
    printOut(entry, `<span class="dim">${esc(d.total ?? members.length)} member(s) in ${esc(id)}</span>\n` +
      members.map(m => esc(m)).join("\n"));
  },
  async "room admin"(entry, args){
    const [room, user] = args;
    if(!room || !user) return printError(entry, "usage: room admin <!room:id> <@user:server>");
    const d = await api(`/api/rooms/${encodeURIComponent(room)}/make_admin`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({user_id:user})});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("ok","ok")} ${esc(user)} is room admin in ${esc(room)}`);
  },
  async "room purge"(entry, args){
    const room = args[0];
    if(!room) return printError(entry, "usage: room purge <!room:id>");
    printOut(entry, `<div class="stamp">【 捺印待機 : ROOM PURGE ARMED 】</div>\n` +
      `<span class="dim">Permanent purge of timeline & events for:</span> <b>${esc(room)}</b>\n` +
      actions([{label:`捺印確認: PURGE ROOM`,cmd:`confirm purge ${room}`,cls:"seal"}]));
    handlers[`confirm purge ${room}`] = async (e2) => {
      const d = await api(`/api/rooms/${encodeURIComponent(room)}`, {method:"DELETE", headers:{"Content-Type":"application/json"}, body:JSON.stringify({purge:true, block:false})});
      if(d.error) return printError(e2, d.error);
      printOut(e2, `<div class="stamp">【 執行済 : ROOM PURGED 】</div> ${esc(JSON.stringify(d))}`);
      delete handlers[`confirm purge ${room}`];
    };
  },
  async fed(entry){
    const d = await api("/api/federation");
    const rows = (d.destinations || []).map(f => [
      `<b>${esc(f.destination)}</b>`,
      f.failure_ts ? badge("failing","bad") : badge("connected","ok"),
      esc(fmtTs(f.failure_ts)),
      esc(fmtTs(f.retry_last_ts)),
      esc(f.last_successful_stream_ordering ?? "-")
    ]);
    printOut(entry, (rows.length ? table(["destination","state","failed","last retry","stream"], rows) : `<span class="dim">no destinations</span>`) +
      `<span class="dim"> total ${esc(d.total ?? rows.length)} · reset with: fed reset &lt;host&gt;</span>`);
  },
  async "fed reset"(entry, args){
    const host = args[0];
    if(!host) return printError(entry, "usage: fed reset <destination>");
    const d = await api(`/api/federation/${encodeURIComponent(host)}/reset`, {method:"POST"});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("retry reset","ok")} ${esc(host)}`);
  },
  async media(entry){
    const d = await api("/api/media/stats");
    const rows = (d.users || []).map(u => [
      `<b>${esc(u.user_id)}</b>`,
      esc(u.displayname || "-"),
      esc(u.media_count ?? 0),
      esc(fmtBytes(u.media_length))
    ]);
    printOut(entry, (rows.length ? table(["user","display","files","storage"], rows) : `<span class="dim">no media stats</span>`) +
      actions([
        {label:"purge cache >30d",cmd:"media purge-cache 30"},
        {label:"quarantine ALL user media",cmd:"media quarantine --all",cls:"danger"},
        {label:"reports",cmd:"reports"}
      ]));
  },
  async "media purge-cache"(entry, args){
    const days = parseInt(args[0] || "30", 10);
    const d = await api(`/api/media/purge_cache?days=${encodeURIComponent(days)}`, {method:"POST"});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("cache purge scheduled","ok")} older than ${days} days`);
  },
  async "media quarantine"(entry, args){
    const user = args[0];
    if(!user) return printError(entry, "usage: media quarantine <@user:server> — or media quarantine --all");
    if(user === "--all"){
      printOut(entry, `<div class="stamp">【 捺印待機 : QUARANTINE ALL MEDIA 】</div>\n` +
        `<span class="dim">Quarantine EVERY user upload across the entire homeserver</span>\n` +
        actions([{label:"捺印確認: QUARANTINE ALL MEDIA",cmd:"confirm quarantine --all",cls:"seal"}]));
      handlers["confirm quarantine --all"] = async (e2) => {
        const d = await api("/api/media/quarantine_all", {method:"POST"});
        if(d.error) return printError(e2, d.error);
        printOut(e2, `<div class="stamp">【 執行済 : ALL MEDIA QUARANTINED 】</div> ${esc(d.num_quarantined ?? 0)} items across ${esc(Object.keys(d.by_user || {}).length)} users`);
        delete handlers["confirm quarantine --all"];
      };
      return;
    }
    const d = await api(`/api/media/quarantine/user/${encodeURIComponent(user)}`, {method:"POST"});
    printOut(entry, `${badge("quarantined","warn")} ${esc(d.num_quarantined ?? 0)} media items from ${esc(user)}`);
  },
  async "media unquarantine"(entry, args){
    const user = args[0];
    if(!user) return printError(entry, "usage: media unquarantine <@user:server>");
    const d = await api(`/api/media/unquarantine/user/${encodeURIComponent(user)}`, {method:"POST"});
    if(d.error) return printError(entry, d.error);
    printOut(entry, `${badge("restored","ok")} media for ${esc(user)} is visible again`);
  },
  async reports(entry){
    const d = await api("/api/reports");
    const rows = (d.event_reports || []).map(r => [
      esc(r.id),
      esc(r.user_id),
      `<b>${esc(r.sender)}</b>`,
      esc(r.reason || "-"),
      esc(fmtTs(r.received_ts))
    ]);
    printOut(entry, rows.length ? table(["id","reporter","sender","reason","received"], rows) : `<span class="dim">no reports</span>`);
  },
  async help(entry){
    printOut(entry, `<span class="dim">reference — click any command below to run it</span>
<span id="cheatsheet">${COMMANDS.map(c => `<b data-cmd="${esc(c.run || c.cmd)}" style="cursor:pointer">${esc(c.cmd)}</b>  —  ${esc(c.desc)}`).join("\n")}</span>`);
  },
  async logout(){ location.href = "/logout"; },
  async clear(){ lineRoot.innerHTML = ""; }
};

function guidedForm(entry, title, fields, onSubmit){
  const wrap = document.createElement("div");
  wrap.className = "out";
  const id = "f" + Math.random().toString(36).slice(2,8);
  wrap.innerHTML = `<span class="dim">${esc(title)}</span>
    <div class="form-block">
      ${fields.map(f => `<label for="${id}-${f.key}">${esc(f.label)}</label><input id="${id}-${f.key}" value="${esc(f.value || "")}" placeholder="${esc(f.placeholder || "")}">`).join("")}
      <div class="row">
        <button class="btn ok" id="${id}-go">${esc(title)}</button>
        <button class="btn" id="${id}-cancel">cancel</button>
      </div>
    </div>`;
  entry.appendChild(wrap);
  scrollback.scrollTop = scrollback.scrollHeight;
  const first = wrap.querySelector("input");
  first && first.focus();
  wrap.querySelector(`#${id}-cancel`).addEventListener("click", () => { wrap.remove(); input.focus(); });
  wrap.querySelector(`#${id}-go`).addEventListener("click", () => {
    const values = {};
    fields.forEach(f => values[f.key] = wrap.querySelector(`#${id}-${f.key}`).value.trim());
    onSubmit(values);
    input.focus();
  });
  fields.forEach(f => {
    wrap.querySelector(`#${id}-${f.key}`).addEventListener("keydown", (ev) => {
      if(ev.key === "Enter"){ ev.preventDefault(); wrap.querySelector(`#${id}-go`).click(); }
    });
  });
}
const FORMS = {
  userNew(entry){
    guidedForm(entry, "create user", [
      {key:"name", label:"username (localpart)", placeholder:"alice"},
      {key:"password", label:"password", placeholder:"(optional, set later)"},
      {key:"display", label:"display name", placeholder:"Alice"},
    ], (v) => {
      if(!v.name) return printError(entry, "username required");
      run(`user new @${v.name}:${SERVER_NAME} ${v.password || ""} ${v.display || ""}`.trim());
    });
  },
  tokenNew(entry){
    guidedForm(entry, "mint registration token", [
      {key:"uses", label:"allowed uses", value:"1", placeholder:"1"},
    ], (v) => run(`token new ${parseInt(v.uses || "1", 10)}`));
  }
};

async function run(raw){
  const cmd = raw.trim();
  if(!cmd) return;
  history.push(cmd);
  historyIndex = history.length;
  const entry = printCmd(cmd);
  const [name, ...args] = cmd.split(/\s+/);
  try{
    if(handlers[cmd]) return await handlers[cmd](entry, []);
    const two = `${name} ${args[0] || ""}`.trim();
    if(handlers[two]) return await handlers[two](entry, args.slice(1));
    if(FORMS[cmd]) return FORMS[cmd](entry);
    if(handlers[name]) return await handlers[name](entry, args);
    printError(entry, `unknown command: ${name}`);
  }catch(e){
    printError(entry, e.message || String(e));
  }
}

let paletteIndex = 0;
function paletteMatches(q){
  q = q.toLowerCase();
  return COMMANDS.filter(c => c.cmd.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q)).slice(0, 12);
}
function renderPalette(){
  const items = paletteMatches(paletteInput.value);
  paletteList.innerHTML = items.map((c, i) =>
    `<div class="palette-item ${i === paletteIndex ? "active" : ""}" data-i="${i}"><span class="k">${esc(c.cmd)}</span><span class="d">${esc(c.desc)}</span></div>`
  ).join("") || `<div class="palette-item"><span class="d">no matches</span></div>`;
  paletteList.querySelectorAll(".palette-item[data-i]").forEach(el => {
    el.addEventListener("click", () => pickPalette(parseInt(el.dataset.i, 10)));
  });
}
function pickPalette(i){
  const items = paletteMatches(paletteInput.value);
  const c = items[i];
  if(!c) return;
  closePalette();
  if(c.form){ run(c.form === "userNew" ? "user new" : "token new"); return; }
  if(c.run && c.run.endsWith(" ")){ input.value = c.run; input.focus(); return; }
  run(c.run || c.cmd);
}
function openPalette(){
  paletteIndex = 0;
  paletteInput.value = "";
  renderPalette();
  palette.classList.add("open");
  paletteInput.focus();
}
function closePalette(){
  palette.classList.remove("open");
  input.focus();
}
paletteInput.addEventListener("input", () => { paletteIndex = 0; renderPalette(); });
paletteInput.addEventListener("keydown", (ev) => {
  const items = paletteMatches(paletteInput.value);
  if(ev.key === "ArrowDown"){ ev.preventDefault(); paletteIndex = Math.min(items.length - 1, paletteIndex + 1); renderPalette(); }
  else if(ev.key === "ArrowUp"){ ev.preventDefault(); paletteIndex = Math.max(0, paletteIndex - 1); renderPalette(); }
  else if(ev.key === "Enter"){ ev.preventDefault(); pickPalette(paletteIndex); }
  else if(ev.key === "Escape"){ closePalette(); }
});

$("prompt").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const value = input.value;
  input.value = "";
  run(value);
});
document.addEventListener("keydown", (ev) => {
  if(ev.ctrlKey && ev.key.toLowerCase() === "k"){
    ev.preventDefault();
    palette.classList.contains("open") ? closePalette() : openPalette();
    return;
  }
  if(ev.key === "/" && document.activeElement !== input && !palette.classList.contains("open")){
    ev.preventDefault();
    input.focus();
  }
  if(ev.ctrlKey && ev.key.toLowerCase() === "l"){
    ev.preventDefault();
    run("clear");
  }
  if(ev.key === "Escape" && palette.classList.contains("open")) closePalette();
});
input.addEventListener("keydown", (ev) => {
  if(ev.key === "ArrowUp"){
    ev.preventDefault();
    if(history.length){
      historyIndex = Math.max(0, historyIndex - 1);
      input.value = history[historyIndex] || "";
      queueMicrotask(() => input.setSelectionRange(input.value.length, input.value.length));
    }
  }else if(ev.key === "ArrowDown"){
    ev.preventDefault();
    historyIndex = Math.min(history.length, historyIndex + 1);
    input.value = history[historyIndex] || "";
  }else if(ev.key === "Tab"){
    ev.preventDefault();
    const prefix = input.value;
    if(!prefix) return;
    const match = COMMANDS.find(c => c.cmd.startsWith(prefix));
    if(match) input.value = match.cmd + " ";
  }
});
lineRoot.addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-cmd]");
  if(btn){ ev.preventDefault(); run(btn.dataset.cmd); return; }
  const copy = ev.target.closest("[data-copy]");
  if(copy){
    ev.preventDefault();
    navigator.clipboard?.writeText(copy.dataset.copy);
    copy.textContent = "copied to clipboard";
    setTimeout(() => { copy.textContent = copy.dataset.copy; }, 1500);
  }
});

refreshHeader();
setInterval(refreshHeader, 30000);
input.focus();
</script>
</body>
</html>
"""


def main():
    app, webui = make_app()
    # Pass app explicitly: bottle.run() defaults to bottle's module-level app
    # singleton, which has none of the routes built above and 404s everything.
    run(
        app=app,
        host=webui.get("host", "127.0.0.1"),
        port=int(webui.get("port", 9099)),
        quiet=True,
    )


if __name__ == "__main__":
    main()