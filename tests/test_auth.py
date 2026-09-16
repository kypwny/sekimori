"""
Tests for the WebUI auth gate.

These run a real WSGI server on a loopback port and drive it over HTTP, so
they exercise the actual request path rather than a mocked one. The
unauthenticated-write test is a regression test: an earlier implementation
returned a 401 from a Bottle before_request hook, which sets the status but
does NOT abort the request (Bottle's trigger_hook discards hook return
values), so the write still executed. Aborting must raise HTTPResponse.
"""
import hashlib
import hmac
import json
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from wsgiref.simple_server import WSGIRequestHandler, make_server

from sekimori import config as config_module
from sekimori.client import AdminClient
from sekimori.web import make_app

PASSWORD = "correct horse battery staple"
SECRET = "a" * 64


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):  # noqa: D102 - silence test server noise
        pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def build_config():
    return {
        "synapse_url": "http://127.0.0.1:9",  # never reached by these tests
        "server_name": "example.test",
        "public_baseurl": "https://matrix.example.test",
        "admin_token": "test-token",
        "db": {"host": "localhost", "name": "synapse", "user": "synapse", "password": ""},
        "webui": {"host": "127.0.0.1", "port": 0, "session_ttl": 3600},
        "webui_password_hash": config_module.hash_password(PASSWORD),
        "secret_key": SECRET,
    }


def signed_session(expiry):
    signature = hmac.new(SECRET.encode(), str(expiry).encode(), hashlib.sha256).hexdigest()
    return f"{expiry}.{signature}"


class AuthGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._original_stats = AdminClient.stats
        AdminClient.stats = lambda self: {
            "server_version": {"server_version": "test-synapse"},
            "client_versions": {"versions": ["v1.11"], "unstable_features": {}},
            "db": {"db_size": "1 MB", "total_events": 1},
            "server_name": "example.test",
        }
        app, _ = make_app(config=build_config())
        cls.server = make_server("127.0.0.1", 0, app, handler_class=QuietHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        AdminClient.stats = cls._original_stats

    def http(self, path, method="GET", data=None, headers=None, timeout=5):
        """Return (status, headers, body) without following redirects."""
        if data is None:
            body = None
        elif isinstance(data, (bytes, bytearray)):
            body = bytes(data)
        else:
            body = urllib.parse.urlencode(data).encode()
        merged = dict(headers or {})
        request = urllib.request.Request(
            self.base + path, data=body, headers=merged, method=method
        )
        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.status, dict(response.headers), response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read().decode()

    def login(self):
        status, headers, _ = self.http(
            "/login", method="POST", data={"password": PASSWORD},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        cookie = headers.get("Set-Cookie", "").split(";")[0]
        self.assertTrue(cookie.startswith("sekimori_session="))
        return cookie

    # ---------------------------------------------------------------- tests
    def test_root_redirects_to_login(self):
        status, headers, _ = self.http("/")
        self.assertEqual(status, 303)
        self.assertTrue(headers.get("Location", "").endswith("/login"))

    def test_api_requires_auth_and_leaks_nothing(self):
        status, _, body = self.http("/api/dashboard")
        self.assertEqual(status, 401)
        payload = json.loads(body)
        self.assertEqual(payload["error"], "unauthorized")
        self.assertNotIn("test-synapse", body)

    def test_unauthenticated_write_is_blocked(self):
        """Regression: the gate must abort, not merely set the status."""
        status, _, body = self.http(
            "/api/tokens", method="POST",
            data=json.dumps({"uses_allowed": 1}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized")

    def test_wrong_password_is_rejected(self):
        status, _, body = self.http(
            "/login", method="POST", data={"password": "wrong"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Incorrect password.", body)

    def test_login_then_authenticated_request(self):
        cookie = self.login()
        status, _, body = self.http("/api/dashboard", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn("test-synapse", body)

    def test_forged_cookie_is_rejected(self):
        status, _, _ = self.http(
            "/api/dashboard", headers={"Cookie": "sekimori_session=9999999999.deadbeef"}
        )
        self.assertEqual(status, 401)

    def test_expired_session_is_rejected(self):
        cookie = f"sekimori_session={signed_session(int(time.time()) - 60)}"
        status, _, _ = self.http("/api/dashboard", headers={"Cookie": cookie})
        self.assertEqual(status, 401)

    def test_valid_but_wrongly_keyed_session_is_rejected(self):
        expiry = int(time.time()) + 600
        signature = hmac.new(b"b" * 64, str(expiry).encode(), hashlib.sha256).hexdigest()
        status, _, _ = self.http(
            "/api/dashboard", headers={"Cookie": f"sekimori_session={expiry}.{signature}"}
        )
        self.assertEqual(status, 401)

    def test_cross_origin_write_is_rejected(self):
        cookie = self.login()
        status, _, body = self.http(
            "/api/tokens", method="POST",
            data=json.dumps({"uses_allowed": 1}).encode(),
            headers={"Content-Type": "application/json", "Cookie": cookie,
                     "Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["errcode"], "M_FORBIDDEN")

    def test_same_origin_write_passes_the_gate(self):
        """A same-origin POST reaches the handler (here it fails on a missing Synapse)."""
        cookie = self.login()
        status, _, body = self.http(
            "/api/tokens", method="POST",
            data=json.dumps({"uses_allowed": 1}).encode(),
            headers={"Content-Type": "application/json", "Cookie": cookie,
                     "Origin": self.base},
        )
        self.assertNotIn(status, (401, 403))


if __name__ == "__main__":
    unittest.main()