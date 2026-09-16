"""
sekimori command line interface.

Destructive operations (deactivate, purge, delete-all) require --yes; without
it they print what would happen and exit non-zero.
"""
import argparse
import datetime
import json
import sys

from . import __version__
from .client import AdminClient
from . import config as config_module


def fmt_ts(value):
    if not value:
        return "-"
    try:
        stamp = float(value)
        if stamp > 1e11:
            stamp /= 1000.0
        return datetime.datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def fmt_bytes(size):
    size = float(size or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.2f} TB"


def print_table(headers, rows):
    if not rows:
        print("no records")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    print(" | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("-+-".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print(" | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def emit(args, headers, rows, raw):
    """Table for humans, JSON for scripts."""
    if getattr(args, "json", False):
        print(json.dumps(raw, indent=2))
    else:
        print_table(headers, rows)


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    return 1


def require_yes(args, action):
    if getattr(args, "yes", False):
        return True
    print(f"refusing without --yes: {action}", file=sys.stderr)
    return False


# ------------------------------------------------------------------ commands
def cmd_info(args, client):
    version = client.server_version()
    versions = client.client_versions()
    db = client.database_summary()
    background = client.background_updates()

    if args.json:
        print(json.dumps(
            {"server_version": version, "client_versions": versions,
             "db": db, "background_updates": background},
            indent=2,
        ))
        return 0

    width = 62
    print("=" * width)
    print(f" sekimori — {client.server_name or 'homeserver'}")
    print("=" * width)
    print(f"Synapse version    : {version.get('server_version', 'unknown')}")
    supported = versions.get("versions") or []
    print(f"Client API versions: {', '.join(supported[-6:]) if supported else 'unavailable'}")
    print(f"MSC features       : {len(versions.get('unstable_features') or {})}")
    if "error" in db:
        print(f"Database           : unavailable ({db['error']})")
    else:
        print(f"Database size      : {db.get('db_size', '?')}")
        print(f"Events             : {int(db.get('total_events') or 0):,} (catalog estimate)")
        print(f"Rooms              : {int(db.get('total_rooms') or 0):,}")
        print(f"Users              : {int(db.get('total_users') or 0):,} local accounts")
        print(f"State events       : {int(db.get('total_state_events') or 0):,} (catalog estimate)")
        print(f"Access tokens      : {int(db.get('total_access_tokens') or 0):,}")
    if "error" not in background:
        running = bool(background.get("current_updates"))
        print(f"Background updates : {'running' if running else 'idle'}")
    print("=" * width)
    return 0


def cmd_users_list(args, client):
    data = client.list_users(limit=args.limit, search_term=args.search,
                             deactivated=True if args.deactivated else None)
    if "error" in data:
        return fail(data["error"])
    users = data.get("users", [])
    rows = [[
        u.get("name"),
        u.get("displayname") or "-",
        "admin" if u.get("admin") else "user",
        "deactivated" if u.get("deactivated") else ("locked" if u.get("locked") else "active"),
        fmt_ts(u.get("last_seen_ts")),
    ] for u in users]
    emit(args, ["user", "display", "role", "state", "last seen"], rows, users)
    if not args.json:
        print(f"\ntotal: {data.get('total', len(users))}")
    return 0


def cmd_users_get(args, client):
    data = client.get_user(args.user_id)
    if "error" in data:
        return fail(data["error"])
    print(json.dumps(data, indent=2))
    return 0


def cmd_users_new(args, client):
    if not args.user_id.startswith("@") or ":" not in args.user_id:
        return fail("user id must look like @name:server")
    data = client.upsert_user(
        args.user_id,
        displayname=args.displayname or args.user_id.split(":")[0].lstrip("@"),
        password=args.password,
        admin=args.admin,
    )
    if "error" in data:
        return fail(data["error"])
    print(f"created {args.user_id}")
    if not args.password:
        print("note: no password set — use: sekimori users passwd <id> <password>")
    return 0


def cmd_users_passwd(args, client):
    data = client.reset_password(args.user_id, args.password, logout_devices=args.logout)
    if "error" in data:
        return fail(data["error"])
    print(f"password reset for {args.user_id}")
    return 0


def cmd_users_admin(args, client):
    data = client.upsert_user(args.user_id, admin=not args.revoke)
    if "error" in data:
        return fail(data["error"])
    print(f"{'revoked' if args.revoke else 'granted'} admin for {args.user_id}")
    return 0


def cmd_users_deactivate(args, client):
    if not require_yes(args, f"deactivate {args.user_id}" +
                       (" and erase their data" if args.erase else "")):
        return 1
    data = client.deactivate_user(args.user_id, erase=args.erase)
    if "error" in data:
        return fail(data["error"])
    print(f"deactivated {args.user_id}")
    return 0


def cmd_users_devices(args, client):
    data = client.user_devices(args.user_id)
    if "error" in data:
        return fail(data["error"])
    devices = data.get("devices", [])
    rows = [[
        d.get("device_id"),
        d.get("display_name") or "-",
        d.get("last_seen_ip") or "-",
        fmt_ts(d.get("last_seen_ts")),
        (d.get("last_seen_user_agent") or "-")[:34],
    ] for d in devices]
    emit(args, ["device", "name", "ip", "last seen", "user agent"], rows, devices)
    return 0


def cmd_users_media(args, client):
    data = client.user_media(args.user_id, limit=args.limit)
    if "error" in data:
        return fail(data["error"])
    media = data.get("media", [])
    rows = [[
        m.get("media_id"),
        m.get("media_type"),
        fmt_bytes(m.get("media_length")),
        m.get("upload_name") or "-",
        fmt_ts(m.get("created_ts")),
        "yes" if m.get("quarantined_by") else "no",
    ] for m in media]
    emit(args, ["media id", "type", "size", "filename", "created", "quarantined"], rows, media)
    if not args.json:
        print(f"\ntotal: {data.get('total', len(media))}")
    return 0


def cmd_rooms_list(args, client):
    data = client.list_rooms(search_term=args.search, limit=args.limit,
                             from_offset=args.offset, order_by=args.order, direction=args.dir)
    if "error" in data:
        return fail(data["error"])
    rooms = data.get("rooms", [])
    rows = [[
        r.get("room_id"),
        (r.get("name") or "unnamed")[:28],
        r.get("joined_members", 0),
        r.get("joined_local_members", 0),
        f"v{r.get('version', '?')}",
        "e2ee" if r.get("encryption") else "clear",
        r.get("state_events", 0),
    ] for r in rooms]
    emit(args, ["room", "name", "members", "local", "ver", "crypto", "state"],
         rows, rooms)
    if not args.json:
        print(f"\ntotal: {data.get('total_rooms', len(rooms))}")
    return 0


def cmd_rooms_get(args, client):
    data = client.get_room(args.room_id)
    if "error" in data:
        return fail(data["error"])
    print(json.dumps(data, indent=2))
    return 0


def cmd_rooms_members(args, client):
    data = client.room_members(args.room_id)
    if "error" in data:
        return fail(data["error"])
    members = data.get("members", [])
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"{len(members)} member(s) in {args.room_id}")
        for member in members:
            print(f"  {member}")
    return 0


def cmd_rooms_extremities(args, client):
    data = client.room_extremities(args.room_id)
    if "error" in data:
        return fail(data["error"])
    print(json.dumps(data, indent=2))
    return 0


def cmd_rooms_make_admin(args, client):
    data = client.make_room_admin(args.room_id, args.user_id)
    if "error" in data:
        return fail(data["error"])
    print(f"{args.user_id} is now room admin in {args.room_id}")
    return 0


def cmd_rooms_purge(args, client):
    if not require_yes(args, f"purge room {args.room_id}" +
                       (" and block it" if args.block else "")):
        return 1
    data = client.delete_room(args.room_id, purge=True, block=args.block)
    if "error" in data:
        return fail(data["error"])
    print(json.dumps(data, indent=2))
    return 0


def cmd_tokens_list(args, client):
    data = client.list_tokens()
    if "error" in data:
        return fail(data["error"])
    tokens = data.get("registration_tokens", [])
    rows = [[
        t.get("token"),
        t.get("uses_allowed") if t.get("uses_allowed") is not None else "unlimited",
        t.get("completed", 0),
        t.get("pending", 0),
        fmt_ts(t.get("expiry_time")),
    ] for t in tokens]
    emit(args, ["token", "uses", "done", "pending", "expires"], rows, tokens)
    return 0


def cmd_tokens_new(args, client):
    data = client.create_token(token=args.token, uses_allowed=args.uses,
                               expiry_time=args.expiry)
    if "error" in data:
        return fail(data["error"])
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"token:    {data.get('token')}")
        print(f"register: {client.registration_url(data.get('token'))}")
    return 0


def cmd_tokens_del(args, client):
    if args.token == "--all":
        if not require_yes(args, "delete ALL registration tokens"):
            return 1
        deleted, failed = client.delete_all_tokens()
        print(json.dumps({"deleted": deleted, "failed": failed}, indent=2))
        return 1 if failed else 0
    data = client.delete_token(args.token)
    if "error" in data:
        return fail(data["error"])
    print(f"deleted {args.token}")
    return 0


def cmd_federation_list(args, client):
    data = client.list_destinations(limit=args.limit, order_by=args.order, direction=args.dir)
    if "error" in data:
        return fail(data["error"])
    destinations = data.get("destinations", [])
    rows = [[
        d.get("destination"),
        "failing" if d.get("failure_ts") else "connected",
        fmt_ts(d.get("failure_ts")),
        fmt_ts(d.get("retry_last_ts")),
        round((d.get("retry_interval") or 0) / 1000),
    ] for d in destinations]
    emit(args, ["destination", "state", "first failure", "last retry", "retry s"],
         rows, destinations)
    if not args.json:
        print(f"\ntotal: {data.get('total', len(destinations))}")
    return 0


def cmd_federation_reset(args, client):
    data = client.reset_destination(args.destination)
    if "error" in data:
        return fail(data["error"])
    print(f"reset retry timing for {args.destination}")
    return 0


def cmd_media_stats(args, client):
    data = client.media_statistics(limit=args.limit, order_by=args.order, direction=args.dir)
    if "error" in data:
        return fail(data["error"])
    users = data.get("users", [])
    rows = [[
        u.get("user_id"),
        u.get("displayname") or "-",
        u.get("media_count", 0),
        fmt_bytes(u.get("media_length")),
    ] for u in users]
    emit(args, ["user", "display", "files", "storage"], rows, users)
    return 0


def cmd_media_quarantine(args, client):
    if args.user_id == "--all":
        stats = client.media_statistics(limit=1000)
        if "error" in stats:
            return fail(stats["error"])
        targets = [u["user_id"] for u in stats.get("users", [])]
        if not require_yes(args, f"quarantine media for ALL {len(targets)} users"):
            return 1
        total, per_user = 0, {}
        for user_id in targets:
            result = client.quarantine_user_media(user_id)
            count = result.get("num_quarantined", 0)
            per_user[user_id] = count
            total += count
        print(json.dumps({"num_quarantined": total, "by_user": per_user}, indent=2))
        return 0
    data = client.quarantine_user_media(args.user_id)
    if "error" in data:
        return fail(data["error"])
    print(f"quarantined {data.get('num_quarantined', 0)} item(s) for {args.user_id}")
    return 0


def cmd_media_unquarantine(args, client):
    data = client.unquarantine_user_media(args.user_id)
    if "error" in data:
        return fail(data["error"])
    print(f"unquarantined media for {args.user_id}")
    return 0


def cmd_media_purge_cache(args, client):
    if not require_yes(args, f"purge cached remote media older than {args.days} days"):
        return 1
    now_ms = int(datetime.datetime.now().timestamp() * 1000)
    data = client.purge_media_cache(now_ms - args.days * 86400 * 1000)
    if "error" in data:
        return fail(data["error"])
    print(json.dumps(data, indent=2))
    return 0


def cmd_reports(args, client):
    data = client.event_reports(limit=args.limit)
    if "error" in data:
        return fail(data["error"])
    reports = data.get("event_reports", [])
    rows = [[
        r.get("id"),
        r.get("user_id"),
        r.get("sender"),
        (r.get("reason") or "-")[:34],
        fmt_ts(r.get("received_ts")),
    ] for r in reports]
    emit(args, ["id", "reporter", "sender", "reason", "received"], rows, reports)
    return 0


# -------------------------------------------------------------------- parser
def build_parser():
    parser = argparse.ArgumentParser(
        prog="sekimori",
        description="Checkpoint keeper for Matrix homeservers — admin CLI and WebUI.",
    )
    parser.add_argument("--config", help="config path (default $SEKIMORI_CONFIG or "
                                        "/etc/sekimori/config.json)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--version", action="version", version=f"sekimori {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_yes(sp):
        sp.add_argument("--yes", action="store_true", help="confirm a destructive action")

    info = sub.add_parser("info", help="server and database census")
    info.set_defaults(func=cmd_info)

    users = sub.add_parser("users", help="manage user accounts")
    users_sub = users.add_subparsers(dest="user_command", required=True)

    u = users_sub.add_parser("list", help="list users")
    u.add_argument("--limit", type=int, default=25)
    u.add_argument("--search")
    u.add_argument("--deactivated", action="store_true", help="only deactivated users")
    u.set_defaults(func=cmd_users_list)

    u = users_sub.add_parser("get", help="raw user record")
    u.add_argument("user_id")
    u.set_defaults(func=cmd_users_get)

    u = users_sub.add_parser("new", help="create or update a user")
    u.add_argument("user_id")
    u.add_argument("--displayname")
    u.add_argument("--password")
    u.add_argument("--admin", action="store_true")
    u.set_defaults(func=cmd_users_new)

    u = users_sub.add_parser("passwd", help="reset a user's password")
    u.add_argument("user_id")
    u.add_argument("password")
    u.add_argument("--logout", action="store_true", help="log out all sessions")
    u.set_defaults(func=cmd_users_passwd)

    u = users_sub.add_parser("admin", help="grant or revoke server admin")
    u.add_argument("user_id")
    u.add_argument("--revoke", action="store_true")
    u.set_defaults(func=cmd_users_admin)

    u = users_sub.add_parser("deactivate", help="deactivate an account")
    u.add_argument("user_id")
    u.add_argument("--erase", action="store_true", help="also erase personal data")
    add_yes(u)
    u.set_defaults(func=cmd_users_deactivate)

    u = users_sub.add_parser("devices", help="list sessions/devices")
    u.add_argument("user_id")
    u.set_defaults(func=cmd_users_devices)

    u = users_sub.add_parser("media", help="list a user's uploaded media")
    u.add_argument("user_id")
    u.add_argument("--limit", type=int, default=25)
    u.set_defaults(func=cmd_users_media)

    rooms = sub.add_parser("rooms", help="inspect and manage rooms")
    rooms_sub = rooms.add_subparsers(dest="room_command", required=True)

    r = rooms_sub.add_parser("list", help="list rooms")
    r.add_argument("--search")
    r.add_argument("--limit", type=int, default=25)
    r.add_argument("--offset", type=int, default=0)
    r.add_argument("--order", default="joined_members")
    r.add_argument("--dir", default="b")
    r.set_defaults(func=cmd_rooms_list)

    r = rooms_sub.add_parser("get", help="raw room record")
    r.add_argument("room_id")
    r.set_defaults(func=cmd_rooms_get)

    r = rooms_sub.add_parser("members", help="list room members")
    r.add_argument("room_id")
    r.set_defaults(func=cmd_rooms_members)

    r = rooms_sub.add_parser("extremities", help="state DAG forward extremities")
    r.add_argument("room_id")
    r.set_defaults(func=cmd_rooms_extremities)

    r = rooms_sub.add_parser("make-admin", help="promote a user in a room")
    r.add_argument("room_id")
    r.add_argument("user_id")
    r.set_defaults(func=cmd_rooms_make_admin)

    r = rooms_sub.add_parser("purge", help="delete and purge a room")
    r.add_argument("room_id")
    r.add_argument("--block", action="store_true", help="block future joins")
    add_yes(r)
    r.set_defaults(func=cmd_rooms_purge)

    tokens = sub.add_parser("tokens", help="registration tokens")
    tokens_sub = tokens.add_subparsers(dest="token_command", required=True)

    t = tokens_sub.add_parser("list", help="list registration tokens")
    t.set_defaults(func=cmd_tokens_list)

    t = tokens_sub.add_parser("new", help="create a registration token")
    t.add_argument("--token", help="custom token string")
    t.add_argument("--uses", type=int, default=1)
    t.add_argument("--expiry", type=int, help="expiry as epoch milliseconds")
    t.set_defaults(func=cmd_tokens_new)

    t = tokens_sub.add_parser("del", help="delete a token, or --all")
    t.add_argument("token", help="token string, or --all")
    add_yes(t)
    t.set_defaults(func=cmd_tokens_del)

    federation = sub.add_parser("federation", help="federation destinations")
    federation_sub = federation.add_subparsers(dest="federation_command", required=True)

    f = federation_sub.add_parser("list", help="list destinations")
    f.add_argument("--limit", type=int, default=25)
    f.add_argument("--order", default="destination")
    f.add_argument("--dir", default="f")
    f.set_defaults(func=cmd_federation_list)

    f = federation_sub.add_parser("reset", help="reset retry timing for a destination")
    f.add_argument("destination")
    f.set_defaults(func=cmd_federation_reset)

    media = sub.add_parser("media", help="media and disk maintenance")
    media_sub = media.add_subparsers(dest="media_command", required=True)

    m = media_sub.add_parser("stats", help="storage usage by user")
    m.add_argument("--limit", type=int, default=20)
    m.add_argument("--order", default="media_length")
    m.add_argument("--dir", default="b")
    m.set_defaults(func=cmd_media_stats)

    m = media_sub.add_parser("quarantine", help="quarantine a user's media, or --all")
    m.add_argument("user_id", help="@user:server, or --all")
    add_yes(m)
    m.set_defaults(func=cmd_media_quarantine)

    m = media_sub.add_parser("unquarantine", help="restore a user's quarantined media")
    m.add_argument("user_id")
    m.set_defaults(func=cmd_media_unquarantine)

    m = media_sub.add_parser("purge-cache", help="purge cached remote media")
    m.add_argument("days", nargs="?", type=int, default=30)
    add_yes(m)
    m.set_defaults(func=cmd_media_purge_cache)

    reports = sub.add_parser("reports", help="abuse and event reports")
    reports.add_argument("--limit", type=int, default=25)
    reports.set_defaults(func=cmd_reports)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "info" and not config_module.load(args.config).get("synapse_url"):
        return fail("no config found; run sekimori-setup first")
    client = AdminClient(config_path=args.config)
    return args.func(args, client) or 0


if __name__ == "__main__":
    sys.exit(main())