#!/usr/bin/env python3
"""alys.py — Alysis Code device-login harvest tool.

Flow per account (verified live 2026-09-09):
  1. POST /functions/v1/device-code          (anon key, no auth) -> device_code + user_code
  2. Sign in at alysiscode.com (Supabase GoTrue: password grant or Google OAuth)
  3. POST /rest/v1/rpc/approve_device        (user JWT, p_user_code)  [web-side approval]
  4. POST /functions/v1/device-token         (anon key) -> approved + slk_ key
  5. Key is a long-lived OpenAI-compatible gateway Bearer against
     https://vzigujbcjjmpntxhmyvr.supabase.co/functions/v1/llm/v1

Usage:
  python3 alys.py [menu]        # Interactive CLI menu runner
  python3 alys.py import  [--file akun.txt]
  python3 alys.py batch   [--file akun.txt] [--stored] [--workers N] [--count N]
                          [--mode both|remote|cli] [--out keys.txt]
  python3 alys.py harvest --email a@b.c [--password '...'] [--mode both|remote|cli]
  python3 alys.py status
  python3 alys.py config
  python3 alys.py models  --key slk_...
  python3 alys.py glogin  [--count N] [--mode both|remote|cli] [--tag s]
akun.txt format (one account per line, blank lines and # comments skipped):
  email:password
  email|password        # any of : , ; | TAB as the first separator
  email                 # no password -> reuse stored refresh_token or state password
"""

import argparse
import base64
import concurrent.futures
import hashlib
import http.cookiejar
import http.server
import json
import random
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

SUPABASE_URL = "https://vzigujbcjjmpntxhmyvr.supabase.co"
SITE = "https://alysiscode.com"
GATEWAY = f"{SUPABASE_URL}/functions/v1/llm/v1"
ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZ6aWd1amJjamptcG50eGhteXZyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODA5Mzc0NTIsImV4cCI6MjA5NjUxMzQ1Mn0."
    "vLH9q-BNO8IWIZrVlvCw8pZWXdLgmKG4Tl9toTTD3pg"
)
STATE_DIR = Path(__file__).resolve().parent / "state"
STATE_FILE = STATE_DIR / "harvest.json"
ACCOUNTS_FILE = "akun.txt"
CONFIG_FILE = STATE_DIR.parent / "config.json"
_STATE_LOCK = threading.RLock()

UA = "alys-harvest/1.0"


@dataclass
class DeviceGrant:
    device_code: str
    user_code: str
    expires_in: int
    interval: int


@dataclass
class AccountRecord:
    email: str
    access_token: str | None = None
    refresh_token: str | None = None
    user_id: str | None = None
    slk_keys: list[str] = field(default_factory=list)
    approved_codes: list[str] = field(default_factory=list)
    updated_at: str = ""


# --------------------------------------------------------------------------- #
# HTTP core
# --------------------------------------------------------------------------- #
def http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: dict | None = None,
    timeout: float = 20.0,
) -> tuple[int, dict | list | str]:
    data = json.dumps(payload).encode() if payload is not None else None
    base = {
        "User-Agent": UA,
        "Content-Type": "application/json",
        "apikey": ANON_KEY,
        "Authorization": f"Bearer {ANON_KEY}",
    }
    if headers:
        for k, v in headers.items():
            if k.lower() == "authorization":
                base[k] = v
            else:
                base[k] = v
    req = urllib.request.Request(url, data=data, headers=base, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, {"error": f"network: {exc}"}
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def as_dict(obj) -> dict:
    return obj if isinstance(obj, dict) else {}


# --------------------------------------------------------------------------- #
# Supabase GoTrue (web session)
# --------------------------------------------------------------------------- #
def auth_password(email: str, password: str) -> tuple[int, dict]:
    """POST /auth/v1/token?grant_type=password -> {access_token, refresh_token, user}"""
    return http_json(
        "POST",
        f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
        headers={"Content-Type": "application/json", "apikey": ANON_KEY},
        payload={"email": email, "password": password},
    )


def auth_refresh(refresh_token: str) -> tuple[int, dict]:
    return http_json(
        "POST",
        f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
        headers={"Content-Type": "application/json", "apikey": ANON_KEY},
        payload={"refresh_token": refresh_token},
    )


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, code_challenge) — mirrors supabase auth-js li()/di()."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    verifier = "".join(secrets.choice(alphabet) for _ in range(56))
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def oauth_authorize_url(redirect_to: str, verifier: str) -> str:
    """GET /auth/v1/authorize — same shape auth-js _getUrlForProvider builds."""
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    q = urllib.parse.urlencode({
        "provider": "google",
        "redirect_to": redirect_to,
        "code_challenge": challenge,
        "code_challenge_method": "s256",
    })
    return f"{SUPABASE_URL}/auth/v1/authorize?{q}"


def pkce_exchange(code: str, verifier: str, redirect_to: str) -> tuple[int, dict]:
    """POST /auth/v1/token?grant_type=pkce — auth code + verifier -> session."""
    return http_json(
        "POST",
        f"{SUPABASE_URL}/auth/v1/token?grant_type=pkce",
        headers={"Content-Type": "application/json", "apikey": ANON_KEY},
        payload={
            "auth_code": code,
            "code_verifier": verifier,
            "redirect_to": redirect_to,
        },
    )


# --------------------------------------------------------------------------- #
# Device-code harvest
# --------------------------------------------------------------------------- #
def request_device_code(client_name: str = "alysis-cli") -> tuple[int, DeviceGrant | None]:
    status, body = http_json(
        "POST",
        f"{SUPABASE_URL}/functions/v1/device-code",
        payload={"client_name": client_name[:80]},
    )
    d = as_dict(body)
    if status != 200 or not d.get("device_code") or not d.get("user_code"):
        return status, None
    grant = DeviceGrant(
        device_code=str(d["device_code"]),
        user_code=str(d["user_code"]),
        expires_in=int(d.get("expires_in", 900)),
        interval=int(d.get("interval", 5)),
    )
    return status, grant


def approve_device(access_token: str, user_code: str) -> tuple[int, dict]:
    """RPC approve_device — requires an authenticated user JWT (web approval)."""
    return http_json(
        "POST",
        f"{SUPABASE_URL}/rest/v1/rpc/approve_device",
        headers={"Authorization": f"Bearer {access_token}"},
        payload={"p_user_code": user_code},
    )


def poll_device_token(grant: DeviceGrant, *, timeout_s: int = 120) -> tuple[str, str | None]:
    """Poll device-token until approved/denied/expired. Returns (status, slk_key)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status, body = http_json(
            "POST",
            f"{SUPABASE_URL}/functions/v1/device-token",
            payload={"device_code": grant.device_code},
        )
        d = as_dict(body)
        st = str(d.get("status", "")).lower()
        if st == "approved":
            return "approved", str(d.get("key") or "").strip() or None
        if st in {"denied", "expired", "not_found", "already_claimed"}:
            return st, None
        time.sleep(max(grant.interval, 1))
    return "timeout", None


# --------------------------------------------------------------------------- #
# Gateway helpers
# --------------------------------------------------------------------------- #
def gateway_models(key: str) -> tuple[int, dict | str]:
    return http_json(
        "GET",
        f"{GATEWAY}/models",
        headers={"Authorization": f"Bearer {key}"},
    )


def gateway_logout(key: str) -> tuple[int, dict | str]:
    return http_json(
        "POST",
        f"{GATEWAY}/logout",
        headers={"Authorization": f"Bearer {key}"},
        payload={},
    )


# --------------------------------------------------------------------------- #
# Configuration (9router / tmpmail)
# --------------------------------------------------------------------------- #
def load_config() -> dict:
    """Load 9router and tmpmail configuration from config.json if present."""
    for candidate in (CONFIG_FILE, Path("config.json")):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
    return {}


# --------------------------------------------------------------------------- #
# 9router Remote Dashboard API Client
# --------------------------------------------------------------------------- #
R9_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
_9ROUTER_CLIENT: dict = {
    "opener": None,
    "dashboard_url": "",
    "node_id": "",
    "logged_in_at": 0,
}


def get_9router_opener(dashboard_url: str, password: str):
    """Authenticate with 9router dashboard and return an opener with session cookie."""
    now = time.time()
    cached_url = _9ROUTER_CLIENT.get("dashboard_url")
    cached_opener = _9ROUTER_CLIENT.get("opener")
    if cached_opener and cached_url == dashboard_url and (now - _9ROUTER_CLIENT.get("logged_in_at", 0)) < 1800:
        return cached_opener

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    login_url = dashboard_url.rstrip("/") + "/api/auth/login"
    login_req = urllib.request.Request(
        login_url,
        data=json.dumps({"password": password}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": R9_UA}
    )
    try:
        with opener.open(login_req, timeout=15) as resp:
            if resp.status != 200:
                raise RuntimeError(f"9router login returned HTTP {resp.status}")
    except Exception as exc:
        raise RuntimeError(f"Gagal login ke 9router ({login_url}): {exc}")

    _9ROUTER_CLIENT["opener"] = opener
    _9ROUTER_CLIENT["dashboard_url"] = dashboard_url
    _9ROUTER_CLIENT["logged_in_at"] = now
    return opener


def resolve_9router_node(dashboard_url: str, opener, configured_node: str = "", node_prefix: str = "ali") -> str:
    """Find target provider node ID (configured or matched by prefix/name/baseUrl)."""
    if configured_node and configured_node != "alysis":
        return configured_node

    if _9ROUTER_CLIENT.get("node_id") and _9ROUTER_CLIENT.get("dashboard_url") == dashboard_url:
        return _9ROUTER_CLIENT["node_id"]

    nodes_url = dashboard_url.rstrip("/") + "/api/provider-nodes"
    req = urllib.request.Request(nodes_url, headers={"User-Agent": R9_UA})
    with opener.open(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    nodes = data.get("nodes", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

    for n in nodes:
        if n.get("prefix") == node_prefix or n.get("name") == node_prefix:
            node_id = n.get("id")
            _9ROUTER_CLIENT["node_id"] = node_id
            return node_id

    for n in nodes:
        base_url = n.get("baseUrl", "")
        if "vzigujbcjjmpntxhmyvr.supabase.co" in base_url or "supabase.co" in base_url:
            node_id = n.get("id")
            _9ROUTER_CLIENT["node_id"] = node_id
            return node_id

    if configured_node:
        return configured_node
    raise RuntimeError(f"Tidak dapat menemukan provider-node dengan prefix '{node_prefix}' di 9router.")


def push_key_to_9router(key: str, name: str = "", default_model: str = "deepseek-v4-flash",
                        cfg: dict | None = None) -> tuple[bool, str]:
    """Push an slk_ key into 9router provider connections."""
    if cfg is None:
        cfg = load_config()
    r9_cfg = cfg.get("9router", {})
    dash_url = r9_cfg.get("dashboard_url")
    password = r9_cfg.get("password")
    if not dash_url or not password:
        return False, "9router dashboard_url atau password belum dikonfigurasi di config.json"

    conn_name = name or f"alysis-{key[-6:]}"
    try:
        opener = get_9router_opener(dash_url, password)
        node_id = resolve_9router_node(
            dash_url,
            opener,
            configured_node=r9_cfg.get("provider_id", ""),
            node_prefix=r9_cfg.get("node_prefix", "ali")
        )

        body = {
            "provider": node_id,
            "name": conn_name,
            "apiKey": key,
            "defaultModel": default_model
        }
        add_url = dash_url.rstrip("/") + "/api/providers"
        req = urllib.request.Request(
            add_url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": R9_UA}
        )
        with opener.open(req, timeout=15) as resp:
            if resp.status in (200, 201):
                res_data = json.loads(resp.read().decode("utf-8"))
                conn = res_data.get("connection", {})
                conn_id = conn.get("id", "ok")
                return True, f"Tersambung ke 9router [node {node_id[:12]}..., name={conn_name}, id={conn_id[:8]}...]"
            return False, f"HTTP {resp.status}"
    except Exception as exc:
        return False, f"Gagal push ke 9router: {exc}"


def get_9router_stats(cfg: dict | None = None) -> dict:
    """Get connection count and status for Alysis node in 9router."""
    if cfg is None:
        cfg = load_config()
    r9_cfg = cfg.get("9router", {})
    dash_url = r9_cfg.get("dashboard_url")
    password = r9_cfg.get("password")
    if not dash_url or not password:
        return {"status": "unconfigured"}
    try:
        opener = get_9router_opener(dash_url, password)
        node_id = resolve_9router_node(
            dash_url,
            opener,
            configured_node=r9_cfg.get("provider_id", ""),
            node_prefix=r9_cfg.get("node_prefix", "ali")
        )
        conns_url = dash_url.rstrip("/") + "/api/providers"
        req = urllib.request.Request(conns_url, headers={"User-Agent": R9_UA})
        with opener.open(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        conns = data.get("connections", [])
        ali_conns = [c for c in conns if c.get("provider") == node_id]
        active_count = sum(1 for c in ali_conns if c.get("testStatus") == "active")
        return {
            "status": "connected",
            "node_id": node_id,
            "total_connections": len(ali_conns),
            "active_connections": active_count,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
def load_state() -> dict:
    with _STATE_LOCK:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text())
                if isinstance(data, dict):
                    return data
            except ValueError:
                pass
        return {"accounts": {}}


def save_state(state: dict) -> None:
    """Merge in-memory accounts into on-disk state, then write. Thread-safe."""
    with _STATE_LOCK:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        disk: dict = {"accounts": {}}
        if STATE_FILE.exists():
            try:
                loaded = json.loads(STATE_FILE.read_text())
                if isinstance(loaded, dict):
                    disk = loaded
            except ValueError:
                pass
        accounts = disk.setdefault("accounts", {})
        for email, rec in list((state.get("accounts") or {}).items()):
            prev = accounts.get(email) or {}
            merged = dict(prev)
            for field_name, value in rec.items():
                if value is not None:
                    merged[field_name] = value
            for list_field in ("slk_keys", "approved_codes"):
                seen = list(prev.get(list_field) or [])
                for value in rec.get(list_field) or []:
                    if value not in seen:
                        seen.append(value)
                merged[list_field] = seen
            merged["email"] = email
            accounts[email] = merged
            rec.clear()
            rec.update(merged)
        STATE_FILE.write_text(json.dumps(disk, indent=2, sort_keys=True))
        STATE_FILE.chmod(0o600)


def record_for(state: dict, email: str) -> dict:
    accounts = state.setdefault("accounts", {})
    rec = accounts.get(email) or {
        "email": email,
        "password": None,
        "access_token": None,
        "refresh_token": None,
        "user_id": None,
        "slk_keys": [],
        "approved_codes": [],
    }
    accounts[email] = rec
    return rec


def upsert(rec: dict, field_name: str, value, unique: bool = False) -> None:
    if value is None:
        return
    if unique:
        lst = rec.setdefault(field_name, [])
        if value not in lst:
            lst.append(value)
    else:
        rec[field_name] = value


# --------------------------------------------------------------------------- #
# Harvest
# --------------------------------------------------------------------------- #
_CAMOUFOX_LOCK = threading.Lock()


def login_google_oauth(
    email: str = "",
    password: str = "",
    *,
    headless: bool = True,
    timeout_s: int = 60,
    port: int = 0,
    log: Callable[[str], None] = print
) -> tuple[dict | None, str]:
    """Automated or interactive Google OAuth (PKCE) flow using Camoufox.

    If email and password are provided, automates Google sign-in and consent.
    If empty, opens interactive Camoufox window for manual login.
    Returns (session_dict, error_message).
    """
    try:
        from camoufox.sync_api import Camoufox
    except ImportError:
        return None, "camoufox belum terinstall (pip install -U camoufox[geoip] && python3 -m camoufox fetch)"

    callback_q: dict[str, str] = {}

    class _CatchHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            callback_q.update(dict(urllib.parse.parse_qsl(parsed.query)))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>alys Google OAuth OK</h1><p>Silakan kembali ke terminal.</p>")

        def log_message(self, *a):
            pass

    with _CAMOUFOX_LOCK:
        srv = http.server.HTTPServer(("127.0.0.1", port), _CatchHandler)
        srv_port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        redirect_to = f"http://127.0.0.1:{srv_port}/auth/callback"
        verifier, _ = pkce_pair()
        url = oauth_authorize_url(redirect_to, verifier)

        use_headless = headless and bool(email and password)
        h_param = True if use_headless else "virtual"

        try:
            with Camoufox(headless=h_param, i_know_what_im_doing=True) as browser:
                page = browser.new_page()
                page.goto(url, wait_until="networkidle")

                if email and password:
                    # 1. Email step
                    try:
                        email_el = page.wait_for_selector('input[type="email"], #identifierId', timeout=15000)
                        if email_el:
                            email_el.fill(email)
                            btn = page.wait_for_selector('#identifierNext, button:has-text("Next"), button:has-text("Berikutnya")', timeout=8000)
                            if btn:
                                btn.click()
                    except Exception as e:
                        log(f"    [!] GLogin email: {e}")

                    # 2. Password step
                    try:
                        pwd_el = page.wait_for_selector('input[type="password"], input[name="Passwd"]', timeout=15000)
                        if pwd_el:
                            pwd_el.fill(password)
                            pbtn = page.wait_for_selector('#passwordNext, button:has-text("Next"), button:has-text("Berikutnya")', timeout=8000)
                            if pbtn:
                                pbtn.click()
                    except Exception as e:
                        log(f"    [!] GLogin password: {e}")

                    # 3. Consent / Allow step
                    try:
                        cbtn = page.wait_for_selector('button:has-text("Lanjutkan"), button:has-text("Continue"), button:has-text("Allow"), #submit_approve_access', timeout=15000)
                        if cbtn:
                            cbtn.click()
                    except Exception:
                        pass

                deadline = time.monotonic() + timeout_s
                while time.monotonic() < deadline:
                    if callback_q.get("code"):
                        break
                    time.sleep(0.5)

        except Exception as exc:
            srv.shutdown()
            srv.server_close()
            return None, f"Camoufox error: {exc}"

        srv.shutdown()
        srv.server_close()

    code = callback_q.get("code")
    if not code:
        return None, f"Tidak ada auth code di callback (timeout {timeout_s}s)"

    status, body = pkce_exchange(code, verifier, redirect_to)
    sess = as_dict(body)
    access = sess.get("access_token")
    if status != 200 or not access:
        return None, f"PKCE exchange gagal: HTTP {status} {body}"

    return sess, ""


def session_for(email: str, password: str, rec: dict,
                log: Callable[[str], None] = print) -> tuple[str | None, int]:
    """Refresh_token, password grant, or automated Google OAuth."""
    # 1. Stored refresh token is always first and fastest (0.4s, zero browser)
    if rec.get("refresh_token"):
        log("[*] mencoba stored refresh_token…")
        rstatus, rbody = auth_refresh(rec["refresh_token"])
        rsess = as_dict(rbody)
        access = rsess.get("access_token")
        if rstatus == 200 and access:
            rec["access_token"] = access
            rec["refresh_token"] = rsess.get("refresh_token") or rec["refresh_token"]
            return access, 0
        log(f"[!] refresh_token expired / gagal: HTTP {rstatus}")

    effective_password = password or rec.get("password") or ""

    # 2. Try standard password grant if not a Google OAuth domain
    is_google_domain = email.endswith("@gmail.com") or email.endswith("@paragadis.com")
    if effective_password and not is_google_domain:
        status, body = auth_password(email, effective_password)
        sess = as_dict(body)
        access = sess.get("access_token")
        if status == 200 and access:
            rec["access_token"] = access
            rec["refresh_token"] = sess.get("refresh_token")
            rec["user_id"] = as_dict(sess.get("user")).get("id")
            rec["password"] = effective_password
            return access, 0
        log(f"[!] password grant HTTP {status}: {sess.get('msg') or body}")

    # 3. Fallback / direct Google OAuth login via Camoufox
    if effective_password:
        log(f"[*] akun Google OAuth terdeteksi: login via Camoufox headless ({email})...")
        sess, err = login_google_oauth(email, effective_password, headless=True, log=log)
        if sess and sess.get("access_token"):
            rec["access_token"] = sess["access_token"]
            rec["refresh_token"] = sess.get("refresh_token")
            rec["user_id"] = as_dict(sess.get("user")).get("id")
            rec["password"] = effective_password
            log(f"[+] Google OAuth sukses! session tersimpan untuk {email}")
            return rec["access_token"], 0
        else:
            log(f"[!] Google OAuth gagal: {err}")

    if not effective_password:
        log("[!] tidak ada password dan tidak ada refresh_token untuk akun ini")
    return None, 2

def cmd_harvest(args) -> int:
    state = load_state()
    email = args.email
    rec = record_for(state, email)

    password = args.password or rec.get("password") or ""
    if not password and not rec.get("refresh_token"):
        print(f"[!] no password provided and no credentials stored for {email}")
        print(f"    pass --password or import via: python3 alys.py import --file akun.txt")
        return 2

    access, code = session_for(email, password, rec)
    if not access:
        save_state(state)
        return code
    print(f"[+] session OK  user_id={rec.get('user_id') or '?'}")


    n_new = mint_keys(state, rec, access, count=max(1, args.count),
                      tag=args.tag, mode=args.mode)
    save_state(state)
    print(f"[*] {email}: +{n_new} key(s), total {len(rec['slk_keys'])}")
    return 0 if n_new else 1


def mint_keys(state: dict, rec: dict, access_token: str, *, count: int,
              tag: str = "", mode: str = "both",
              log: Callable[[str], None] = print,
              progress: Callable[[int], None] | None = None) -> int:
    """Mint `count` device grants, approve via RPC, poll, persist keys."""
    n_new = 0
    for i in range(max(1, count)):
        tagi = f"[{i + 1}/{count}]"
        dstatus, dbody = request_device_code(client_name=f"alysis-cli @ {tag or 'harvest'}")
        grant = dbody if isinstance(dbody, DeviceGrant) else None
        if dstatus != 200 or grant is None:
            log(f"{tagi} [!] device-code HTTP {dstatus}: {dbody}")
            continue
        log(f"{tagi} [+] user_code={grant.user_code}")

        astatus, abody = approve_device(access_token, grant.user_code)
        if astatus == 200:
            log(f"{tagi} [+] approved via RPC")
            upsert(rec, "approved_codes", grant.user_code, unique=True)
        elif mode in ("both", "remote"):
            log(f"{tagi} [!] RPC approval HTTP {astatus}: {abody}")
            log(f"{tagi}     manual: {SITE}/activate?code={grant.user_code}")

        pstatus, key = poll_device_token(grant, timeout_s=120 if astatus == 200 else 15)
        if pstatus == "approved" and key:
            log(f"{tagi} [+] KEY {key}")
            upsert(rec, "slk_keys", key, unique=True)
            rec["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            save_state(state)
            n_new += 1
            if progress:
                progress(n_new)

            # Auto-push ke 9router jika dikonfigurasi
            cfg = load_config()
            if cfg.get("9router", {}).get("auto_push", True):
                email_name = rec.get("email") or f"alysis-{key[-6:]}"
                key_idx = len(rec.get("slk_keys") or [])
                conn_name = email_name if key_idx <= 1 else f"{email_name}-{key_idx}"
                ok_push, push_info = push_key_to_9router(key, name=conn_name, cfg=cfg)
                if ok_push:
                    log(f"{tagi} [+] 9router auto-push: {push_info}")
                else:
                    log(f"{tagi} [!] 9router: {push_info}")
        else:
            log(f"{tagi} [!] poll: {pstatus}")
        time.sleep(0.4)
    return n_new


def cmd_glogin(args) -> int:
    """Google OAuth (PKCE) via Camoufox -> mint keys."""
    state = load_state()
    batch_mode = getattr(args, "batch", False)
    target_email = getattr(args, "email", None)
    target_pwd = getattr(args, "password", None)

    if batch_mode:
        acc_file = resolve_account_file(getattr(args, "file", None) or "akun.txt")
        if not acc_file:
            print("[!] File akun.txt tidak ditemukan.")
            return 2
        accs = parse_accounts(acc_file)
        if not accs:
            print(f"[!] Tidak ada akun di {acc_file.name}")
            return 2
        print(f"[*] Menjalankan batch Google OAuth untuk {len(accs)} akun dari {acc_file.name}...")
        success_cnt = 0
        for idx, (em, pw) in enumerate(accs, 1):
            rec = record_for(state, em)
            if rec.get("refresh_token") and rec.get("slk_keys"):
                print(f"[{idx}/{len(accs)}] [=] {em}: sudah terautentikasi & memiliki {len(rec['slk_keys'])} key. Skip login.")
                success_cnt += 1
                continue

            print(f"[{idx}/{len(accs)}] [*] Login Google OAuth untuk {em}...")
            sess, err = login_google_oauth(em, pw, headless=True)
            if not sess or not sess.get("access_token"):
                print(f"[{idx}/{len(accs)}] [!] Gagal: {err}")
                continue

            access = sess["access_token"]
            user = as_dict(sess.get("user"))
            rec["access_token"] = access
            rec["refresh_token"] = sess.get("refresh_token")
            rec["user_id"] = user.get("id")
            rec["password"] = pw
            save_state(state)
            print(f"[{idx}/{len(accs)}] [+] Berhasil login! User ID: {rec.get('user_id')}")

            cnt = getattr(args, "count", 1) or 1
            if cnt > 0:
                n_new = mint_keys(state, rec, access, count=cnt, tag=getattr(args, "tag", ""), mode=getattr(args, "mode", "both"))
                save_state(state)
                print(f"[{idx}/{len(accs)}] [*] Minted {n_new} key(s), total {len(rec['slk_keys'])}")
            success_cnt += 1
            time.sleep(1)

        print(f"\n[*] Selesai. {success_cnt}/{len(accs)} akun terproses.")
        return 0

    # Single account or manual consent
    if target_email and target_pwd:
        rec = record_for(state, target_email)
        print(f"[*] Login Google OAuth untuk {target_email}...")
        sess, err = login_google_oauth(target_email, target_pwd, headless=True)
    else:
        email_hint = getattr(args, "email_hint", "google") or "google"
        rec = record_for(state, "glogin:" + email_hint)
        print(f"[*] Membuka browser Camoufox untuk login Google manual...")
        sess, err = login_google_oauth(headless=False, timeout_s=300)

    if not sess or not sess.get("access_token"):
        print(f"[!] Login gagal: {err}")
        return 2

    access = sess["access_token"]
    user = as_dict(sess.get("user"))
    email = (user.get("email") or "").lower() or rec["email"]
    rec = record_for(state, email)
    rec["access_token"] = access
    rec["refresh_token"] = sess.get("refresh_token")
    rec["user_id"] = user.get("id")
    if target_pwd:
        rec["password"] = target_pwd
    save_state(state)
    print(f"[+] session OK  email={email}  user_id={rec.get('user_id')}")

    n_new = mint_keys(state, rec, access, count=max(1, getattr(args, "count", 1)),
                      tag=getattr(args, "tag", ""), mode=getattr(args, "mode", "both"))
    save_state(state)
    print(f"[*] {email}: +{n_new} key(s), total {len(rec['slk_keys'])}")
    return 0 if n_new else 1


# --------------------------------------------------------------------------- #
# Batch & Import (akun.txt)
# --------------------------------------------------------------------------- #
_SEP_RE = re.compile(r"[:|;,\t]")

def parse_accounts(path: str | Path) -> list[tuple[str, str]]:
    """Read accounts.txt -> [(email, password)]. Blank lines and # comments skipped.

    Separator: first ':', '|', ';', ',' or TAB. No separator -> email only
    (session then comes from a stored refresh_token).
    """
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(str(p))
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for lineno, raw in enumerate(p.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _SEP_RE.search(line)
        if m:
            email, password = line[:m.start()].strip(), line[m.end():].strip()
        else:
            email, password = line, ""
        if not email or "@" not in email:
            print(f"[!] {p.name}:{lineno} skipped (not an email): {line[:60]}")
            continue
        key = email.lower()
        if key in seen:
            print(f"[!] {p.name}:{lineno} duplicate, skipped: {email}")
            continue
        seen.add(key)
        out.append((email, password))
    return out

def resolve_account_file(path_str: str | Path | None = None) -> Path | None:
    """Resolve account file path checking akun.txt, accounts.txt and script dir."""
    script_dir = STATE_DIR.parent
    candidates: list[Path] = []

    if path_str:
        p = Path(path_str).expanduser()
        candidates.extend([p, script_dir / p.name])
        if p.name in ("akun.txt", "accounts.txt"):
            for alt in ("akun.txt", "accounts.txt"):
                candidates.extend([Path(alt), script_dir / alt])
    else:
        for name in ("akun.txt", "accounts.txt"):
            candidates.extend([Path(name), script_dir / name])

    seen: set[str] = set()
    for c in candidates:
        try:
            key = str(c.resolve())
        except OSError:
            key = str(c)
        if key in seen:
            continue
        seen.add(key)
        if c.exists() and c.is_file():
            return c
    return None


def cmd_import(args) -> int:
    resolved = resolve_account_file(args.file)
    if not resolved:
        print(f"[!] account file not found: {args.file}")
        print(f"[!] create 'akun.txt' with one 'email:password' per line")
        return 2

    try:
        accounts = parse_accounts(resolved)
    except FileNotFoundError as exc:
        print(f"[!] account list not found: {exc}")
        return 2

    if not accounts:
        print(f"[!] no usable accounts in {resolved.name}")
        return 2

    state = load_state()
    existing = state.setdefault("accounts", {})
    n_new = 0
    n_updated = 0

    for email, password in accounts:
        is_new = email not in existing
        rec = record_for(state, email)
        if password:
            if not is_new and rec.get("password") != password:
                n_updated += 1
            rec["password"] = password
        rec["imported_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        rec["source_file"] = resolved.name
        if is_new:
            n_new += 1

    save_state(state)
    print(f"[+] successfully imported {len(accounts)} account(s) from {resolved.name}")
    print(f"    +{n_new} new, {n_updated} updated, total {len(existing)} account(s) in state")
    print(f"[*] credentials saved to {STATE_FILE}")
    return 0

def run_account(state: dict, email: str, password: str, *, count: int = 1,
                mode: str = "both", tag: str = "") -> dict:
    """Full flow for one account. Never raises; returns a result dict."""
    prefix = f"{email} |"
    res = {"email": email, "status": "error", "keys": 0, "total": 0, "error": ""}

    def log(msg: str) -> None:
        print(f"{prefix} {msg}", flush=True)

    rec = record_for(state, email)
    access, code = session_for(email, password, rec, log=log)
    if not access:
        res["error"] = "auth failed"
        save_state(state)
        return res
    log(f"[+] session OK  user_id={rec.get('user_id') or '?'}")
    res["status"] = "ok"

    try:
        n_new = mint_keys(state, rec, access, count=max(1, count),
                          tag=tag, mode=mode, log=log)
    except Exception as exc:  # network/parse blowups must not kill the batch
        res["error"] = f"{type(exc).__name__}: {exc}"
        log(f"[!] {res['error']}")
        n_new = 0
    save_state(state)

    res["keys"] = n_new
    res["total"] = len(rec.get("slk_keys") or [])
    log(f"[*] +{n_new} key(s), total {res['total']}")
    return res

def write_keys(accounts: dict, path: str | Path) -> int:
    """Dump every slk_ key (one per line) to `path`. Returns key count."""
    keys: list[str] = []
    for rec in (accounts or {}).values():
        for k in rec.get("slk_keys") or []:
            if k not in keys:
                keys.append(k)
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(f"{k}\n" for k in keys))
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return len(keys)

def cmd_batch(args) -> int:
    state = load_state()
    accounts: list[tuple[str, str]] = []

    if getattr(args, "stored", False):
        for email, rec in sorted(state.get("accounts", {}).items()):
            pwd = rec.get("password") or ""
            if pwd or rec.get("refresh_token"):
                accounts.append((email, pwd))
        if not accounts:
            print("[!] no stored accounts with credentials in state")
            print("[!] import first: python3 alys.py import --file akun.txt")
            return 2
        print(f"[*] loaded {len(accounts)} account(s) from state storage")
    else:
        resolved = resolve_account_file(args.file)
        if not resolved:
            stored = [
                (e, rec.get("password") or "")
                for e, rec in sorted(state.get("accounts", {}).items())
                if rec.get("password") or rec.get("refresh_token")
            ]
            if stored and args.file in (ACCOUNTS_FILE, "akun.txt", "accounts.txt"):
                print(f"[*] '{args.file}' not found, falling back to {len(stored)} account(s) in state")
                accounts = stored
            else:
                print(f"[!] account list not found: {args.file}")
                print(f"[!] create 'akun.txt' with one 'email:password' per line, or run:")
                print(f"    python3 alys.py import --file akun.txt")
                return 2
        else:
            try:
                accounts = parse_accounts(resolved)
            except FileNotFoundError as exc:
                print(f"[!] account list not found: {exc}")
                return 2
            if not accounts:
                print(f"[!] no usable accounts in {resolved.name}")
                return 2
    state = load_state()
    workers = args.workers or min(4, len(accounts))
    workers = max(1, min(workers, len(accounts)))
    print(f"[*] {len(accounts)} account(s), {workers} worker(s), "
          f"{max(1, args.count)} key(s) each, mode={args.mode}")

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(run_account, state, email, password,
                        count=max(1, args.count), mode=args.mode, tag=args.tag): email
            for email, password in accounts
        }
        for fut in concurrent.futures.as_completed(futures):
            email = futures[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({"email": email, "status": "error", "keys": 0,
                                "total": 0, "error": f"{type(exc).__name__}: {exc}"})

    save_state(state)
    order = {email: i for i, (email, _) in enumerate(accounts)}
    results.sort(key=lambda r: order.get(r["email"], 1 << 30))

    print("\n" + "=" * 72)
    print(f"{'ACCOUNT':<40} {'STATUS':<8} {'+KEYS':>5} {'TOTAL':>6}")
    print("-" * 72)
    for r in results:
        status = "ok" if r["status"] == "ok" else "fail"
        note = f"  {r['error']}" if r["error"] and r["status"] != "ok" else ""
        print(f"{r['email']:<40} {status:<8} {r['keys']:>5} {r['total']:>6}{note}")
    ok = sum(1 for r in results if r["status"] == "ok")
    new_keys = sum(r["keys"] for r in results)
    print("-" * 72)
    print(f"{ok}/{len(results)} accounts ok, +{new_keys} new key(s)")

    if args.out:
        n = write_keys(state.get("accounts", {}), args.out)
        print(f"[*] wrote {n} key(s) -> {args.out}")

    return 0 if ok else 1

# --------------------------------------------------------------------------- #
# Status / models
# --------------------------------------------------------------------------- #
def cmd_status(args) -> int:
    acc_file = resolve_account_file(getattr(args, "file", None) or "akun.txt")
    file_accs: list[tuple[str, str]] = []
    if acc_file:
        try:
            file_accs = parse_accounts(acc_file)
        except Exception:
            pass

    state = load_state()
    state_accounts = state.get("accounts", {})
    total_keys = sum(len(rec.get("slk_keys") or []) for rec in state_accounts.values())

    print("=" * 68)
    print("                 📊 STATUS RINGKASAN HARVESTER")
    print("=" * 68)

    # 1. File Akun Local
    if acc_file and file_accs:
        print(f"📂 File Akun Local : {acc_file.name} ✅ TERDETEKSI ({len(file_accs)} akun)")
        sample = [e for e, _ in file_accs[:3]]
        sample_str = ", ".join(sample)
        if len(file_accs) > 3:
            sample_str += f", ... (+{len(file_accs) - 3} lainnya)"
        print(f"   Contoh akun     : {sample_str}")
    elif acc_file:
        print(f"📂 File Akun Local : {acc_file.name} ⚠️ (0 akun valid ditemukan)")
    else:
        print("📂 File Akun Local : ❌ 'akun.txt' tidak ditemukan di folder")

    # 2. Database State
    print(f"💾 Database State  : {len(state_accounts)} akun tersimpan | {total_keys} total key slk_")
    print("-" * 68)

    if not state_accounts and not file_accs:
        print("[!] Belum ada akun di state dan file akun.txt belum terisi.")
        print("=" * 68)
        return 0

    if state_accounts:
        print("Detail Akun di Database State:")
        for email, rec in sorted(state_accounts.items()):
            keys = rec.get("slk_keys") or []
            has_pwd = " [password tersimpan]" if rec.get("password") else ""
            user_id = rec.get("user_id") or "?"
            print(f"  • {email}{has_pwd}  keys={len(keys)}  user_id={user_id}")
            for k in keys:
                print(f"      - {k}")
    else:
        print("Detail Akun di Database State: (belum ada akun yang diimpor/diharvest)")

    # 3. Analisis sinkronisasi akun.txt vs state
    if file_accs:
        unimported = [e for e, _ in file_accs if e not in state_accounts]
        no_keys = [e for e, _ in file_accs if not (state_accounts.get(e, {}).get("slk_keys"))]
        print("-" * 68)
        if unimported:
            print(f"⚠️  {len(unimported)} dari {len(file_accs)} akun di {acc_file.name} belum diimpor ke state.")
            print(f"    👉 Jalankan: python3 alys.py import (atau menu [1]) untuk impor.")
        elif no_keys:
            print(f"ℹ️  Semua {len(file_accs)} akun sudah diimpor. {len(no_keys)} akun belum memiliki key slk_.")
            print(f"    👉 Jalankan: python3 alys.py batch (atau menu [2]) untuk harvest.")
        else:
            print(f"✅ Seluruh {len(file_accs)} akun telah diimpor dan memiliki key slk_!")

    print("=" * 68)
    return 0


def cmd_config(args) -> int:
    cfg = load_config()
    if not cfg:
        print(f"[*] no config.json found at {CONFIG_FILE}")
        print(f"    create config.json from config.example.json")
        return 1
    print(f"[+] configuration loaded from {CONFIG_FILE}:")
    print(json.dumps(cfg, indent=2))
    r9_cfg = cfg.get("9router", {})
    if r9_cfg.get("dashboard_url") and r9_cfg.get("password"):
        print("\n[*] Mengetes koneksi ke 9router dashboard...")
        stats = get_9router_stats(cfg)
        if stats.get("status") == "connected":
            print(f"[+] 9router terhubung! Node: {stats.get('node_id')}, Total koneksi saat ini: {stats.get('total_connections')}")
        else:
            print(f"[!] Gagal terhubung ke 9router: {stats.get('error')}")
    return 0


def cmd_sync_9router(args=None) -> int:
    """Sync all harvested slk_ keys in state/harvest.json to 9router provider connections."""
    cfg = load_config()
    r9_cfg = cfg.get("9router", {})
    if not r9_cfg.get("dashboard_url") or not r9_cfg.get("password"):
        print("[!] 9router belum dikonfigurasi lengkap di config.json.")
        print("    Pastikan 'dashboard_url' dan 'password' sudah terisi.")
        return 1

    state = load_state()
    accounts = state.get("accounts", {})
    all_keys: list[tuple[str, str]] = []  # (email, key)
    for em, rec in accounts.items():
        keys = rec.get("slk_keys") or []
        for k in keys:
            all_keys.append((em, k))

    if not all_keys:
        print("[!] Tidak ada API key (slk_*) tersimpan di database state/harvest.json.")
        print("    Jalankan harvest atau glogin terlebih dahulu.")
        return 1

    print(f"[*] Menemukan {len(all_keys)} API key dari {len(accounts)} akun tersimpan.")
    print(f"[*] Menghubungkan ke 9router ({r9_cfg.get('dashboard_url')})...")

    email_key_counter: dict[str, int] = {}
    success_count = 0
    failed_count = 0

    for idx, (em, key) in enumerate(all_keys, 1):
        email_key_counter[em] = email_key_counter.get(em, 0) + 1
        k_idx = email_key_counter[em]
        conn_name = em if k_idx == 1 else f"{em}-{k_idx}"

        ok, msg = push_key_to_9router(key, name=conn_name, cfg=cfg)
        if ok:
            print(f"[{idx}/{len(all_keys)}] [+] {conn_name}: {msg}")
            success_count += 1
        else:
            print(f"[{idx}/{len(all_keys)}] [!] {conn_name}: {msg}")
            failed_count += 1
        time.sleep(0.2)

    print("\n" + "=" * 60)
    print(f"[*] Selesai sync ke 9router: {success_count} berhasil, {failed_count} gagal.")
    print("=" * 60)
    return 0 if failed_count == 0 else 1

def cmd_models(args) -> int:
    status, body = gateway_models(args.key)
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2) if not isinstance(body, str) else body)
    return 0 if status == 200 else 1


def cmd_chat(args) -> int:
    status, body = http_json(
        "POST",
        f"{GATEWAY}/chat/completions",
        headers={"Authorization": f"Bearer {args.key}"},
        payload={
            "model": args.model,
            "messages": [{"role": "user", "content": args.prompt}],
            "max_tokens": args.max_tokens,
        },
        timeout=60.0,
    )
    print(f"HTTP {status}")
    if isinstance(body, dict):
        msg = ((body.get("choices") or [{}])[0].get("message") or {}).get("content")
        if msg:
            print(msg)
        else:
            print(json.dumps(body, indent=2)[:1200])
    else:
        print(body)
    return 0 if status == 200 else 1

def cmd_menu(args=None) -> int:
    """Interactive TUI menu for easy terminal operation."""
    while True:
        acc_file = resolve_account_file("akun.txt")
        file_accs: list[tuple[str, str]] = []
        if acc_file:
            try:
                file_accs = parse_accounts(acc_file)
            except Exception:
                pass

        state = load_state()
        state_accounts = state.get("accounts", {})
        total_keys = sum(len(rec.get("slk_keys") or []) for rec in state_accounts.values())
        cfg = load_config()

        print("\n" + "=" * 68)
        print("        ⚡ ALYSIS CODE KEY HARVESTER — INTERACTIVE CLI ⚡")
        print("=" * 68)

        # Prominent file detection badge
        if acc_file and file_accs:
            unimported = sum(1 for e, _ in file_accs if e not in state_accounts)
            badge = f" ({unimported} belum diimpor ke state)" if unimported > 0 else " (semua tersimpan di state)"
            print(f"  📂 File Akun   : {acc_file.name} ✅ TERDETEKSI ({len(file_accs)} akun siap pakai){badge}")
        elif acc_file:
            print(f"  📂 File Akun   : {acc_file.name} ⚠️ (0 akun valid)")
        else:
            print("  📂 File Akun   : ❌ akun.txt tidak ditemukan di folder ini")

        print(f"  💾 Database    : {len(state_accounts)} akun di state | {total_keys} total key slk_")

        cfg_status = []
        if cfg.get("9router"):
            r9_stats = get_9router_stats(cfg)
            if r9_stats.get("status") == "connected":
                cfg_status.append(f"9router: OK ({r9_stats.get('total_connections', 0)} koneksi)")
            else:
                cfg_status.append("9router: OK")
        if cfg.get("tmpmail"):
            cfg_status.append("tmpmail: OK")
        cfg_str = " | ".join(cfg_status) if cfg_status else "belum ada config.json"
        print(f"  ⚙️  Config      : {cfg_str}")
        print("-" * 68)

        # Action recommendation
        if acc_file and file_accs and any(e not in state_accounts for e, _ in file_accs):
            unimported = sum(1 for e, _ in file_accs if e not in state_accounts)
            print(f"  💡 {unimported} akun di {acc_file.name} belum ada di database state!")
            print("     • Pilih [1] untuk impor kredensial ke database state")
            print("     • Atau pilih [2] untuk langsung jalankan batch harvest")
            print("-" * 68)

        print("  [1] Import Akun        -> Ingest kredensial dari akun.txt ke state")
        print("  [2] Batch Harvesting   -> Minting key paralel untuk akun")
        print("  [3] Single Harvest     -> Minting key untuk 1 akun tertentu")
        print("  [4] Cek Status & Key   -> Detail akun & list key slk_ tersimpan")
        print("  [5] Cek Konfigurasi    -> Cek setting 9router & tmpmail")
        print("  [6] Test API Key       -> Test endpoint /models & chat")
        print("  [7] Google OAuth Login -> Login browser Camoufox (glogin)")
        print("  [8] Sync ke 9router    -> Daftarkan semua key slk_ ke 9router")
        print("  [0] Keluar")
        print("=" * 68)

        try:
            choice = input("Pilih menu [0-8]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Keluar.")
            return 0

        if choice == "0":
            print("[*] Selesai. Keluar.")
            return 0

        elif choice == "1":
            print("\n--- [1] IMPORT AKUN KE STATE ---")
            target_file = str(acc_file) if acc_file else ACCOUNTS_FILE
            if acc_file and file_accs:
                prompt_resp = input(f"File terdeteksi '{acc_file.name}' ({len(file_accs)} akun). Impor sekarang? [Y/n]: ").strip().lower()
                if prompt_resp in ("", "y", "yes"):
                    target_file = str(acc_file)
                else:
                    target_file = input(f"Masukkan path file akun [{ACCOUNTS_FILE}]: ").strip() or ACCOUNTS_FILE
            else:
                target_file = input(f"Path file akun [{target_file}]: ").strip() or target_file

            ns = argparse.Namespace(file=target_file)
            cmd_import(ns)

        elif choice == "2":
            print("\n--- [2] BATCH HARVESTING ---")
            stored = False
            target_file = str(acc_file) if acc_file else ACCOUNTS_FILE

            if acc_file and file_accs and state_accounts:
                print("Pilih sumber akun:")
                print(f"  [1] Dari file '{acc_file.name}' ({len(file_accs)} akun) [DEFAULT]")
                print(f"  [2] Dari database state ({len(state_accounts)} akun)")
                print("  [3] Path file kustom")
                src = input("Pilihan [1]: ").strip() or "1"
                if src == "2":
                    stored = True
                elif src == "3":
                    target_file = input("Path file akun: ").strip() or target_file
            elif acc_file and file_accs:
                print(f"[*] Menggunakan file '{acc_file.name}' ({len(file_accs)} akun).")
            elif state_accounts:
                print(f"[*] Menggunakan database state ({len(state_accounts)} akun tersimpan).")
                stored = True
            else:
                target_file = input(f"Path file akun [{target_file}]: ").strip() or target_file

            cnt_str = input("Jumlah key per akun [1]: ").strip() or "1"
            try:
                cnt = max(1, int(cnt_str))
            except ValueError:
                cnt = 1

            default_workers = min(6, len(file_accs)) if file_accs else 4
            wrk_str = input(f"Jumlah paralel workers [{default_workers}]: ").strip() or str(default_workers)
            try:
                wrk = max(1, int(wrk_str))
            except ValueError:
                wrk = default_workers

            m_input = input("Approval mode ([1] both, [2] remote, [3] cli) [1]: ").strip() or "1"
            mode_map = {"1": "both", "2": "remote", "3": "cli", "both": "both", "remote": "remote", "cli": "cli"}
            mode = mode_map.get(m_input, "both")

            out_file = input("Output file key [keys.txt]: ").strip() or "keys.txt"

            ns = argparse.Namespace(
                file=target_file,
                stored=stored,
                count=cnt,
                workers=wrk,
                mode=mode,
                tag="",
                out=out_file
            )
            cmd_batch(ns)

        elif choice == "3":
            print("\n--- [3] SINGLE ACCOUNT HARVEST ---")
            email = input("Email akun: ").strip()
            if not email:
                print("[!] Email tidak boleh kosong.")
                continue
            pwd = input("Password (kosongkan jika sudah ada di state): ").strip()
            cnt_str = input("Jumlah key [1]: ").strip() or "1"
            try:
                cnt = max(1, int(cnt_str))
            except ValueError:
                cnt = 1

            m_input = input("Approval mode ([1] both, [2] remote, [3] cli) [1]: ").strip() or "1"
            mode_map = {"1": "both", "2": "remote", "3": "cli"}
            mode = mode_map.get(m_input, "both")

            ns = argparse.Namespace(
                email=email,
                password=pwd,
                count=cnt,
                mode=mode,
                tag=""
            )
            cmd_harvest(ns)

        elif choice == "4":
            print("\n--- [4] STATUS AKUN & KEY ---")
            cmd_status(argparse.Namespace())

        elif choice == "5":
            print("\n--- [5] KONFIGURASI (9router & tmpmail) ---")
            cmd_config(argparse.Namespace())

        elif choice == "6":
            print("\n--- [6] TEST API KEY ---")
            state = load_state()
            keys = []
            for rec in state.get("accounts", {}).values():
                keys.extend(rec.get("slk_keys") or [])
            default_key = keys[0] if keys else ""
            prompt_key = f"Key slk_ [{default_key[:12]}...]: " if default_key else "Key slk_: "
            k = input(prompt_key).strip() or default_key
            if not k:
                print("[!] Key tidak ditemukan.")
                continue

            test_type = input("Tipe test ([1] probe models, [2] test chat completion) [1]: ").strip() or "1"
            if test_type == "2":
                p = input("Prompt test [ping]: ").strip() or "ping"
                cmd_chat(argparse.Namespace(key=k, model="deepseek-v4-flash", prompt=p, max_tokens=32))
            else:
                cmd_models(argparse.Namespace(key=k))

        elif choice == "7":
            print("\n--- [7] GOOGLE OAUTH LOGIN (Camoufox) ---")
            print("Pilih mode Google OAuth:")
            print("  [1] Batch Otomatis dari akun.txt (Camoufox Headless) [DEFAULT]")
            print("  [2] Login 1 Akun Google (Input Email & Password)")
            print("  [3] Login Manual Browser Window (Jack Consent)")
            g_choice = input("Pilihan [1-3] [1]: ").strip() or "1"

            cnt_str = input("Jumlah key slk_ per akun [1]: ").strip() or "1"
            try:
                cnt = max(1, int(cnt_str))
            except ValueError:
                cnt = 1

            m_input = input("Approval mode ([1] both, [2] remote, [3] cli) [1]: ").strip() or "1"
            mode_map = {"1": "both", "2": "remote", "3": "cli"}
            mode = mode_map.get(m_input, "both")

            if g_choice == "1":
                target_file = str(acc_file) if acc_file else ACCOUNTS_FILE
                target_file = input(f"File akun [{target_file}]: ").strip() or target_file
                ns = argparse.Namespace(
                    batch=True,
                    file=target_file,
                    email=None,
                    password=None,
                    count=cnt,
                    mode=mode,
                    tag="",
                    email_hint="google",
                    port=0
                )
            elif g_choice == "2":
                em = input("Email Google: ").strip()
                pw = input("Password: ").strip()
                ns = argparse.Namespace(
                    batch=False,
                    email=em,
                    password=pw,
                    count=cnt,
                    mode=mode,
                    tag="",
                    email_hint="google",
                    port=0
                )
            else:
                ns = argparse.Namespace(
                    batch=False,
                    email=None,
                    password=None,
                    count=cnt,
                    mode=mode,
                    tag="",
                    email_hint="google",
                    port=0
                )
            cmd_glogin(ns)
        elif choice == "8":
            print("\n--- [8] SYNC SEMUA KEY KE 9ROUTER ---")
            cmd_sync_9router(argparse.Namespace())
        else:
            print("[!] Pilihan tidak valid.")

        try:
            input("\n[Tekan ENTER untuk kembali ke menu...]")
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Keluar.")
            return 0

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    if len(sys.argv) == 1:
        return cmd_menu(None)

    ap = argparse.ArgumentParser(description="Alysis device-login harvest tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("menu", help="interactive CLI menu").set_defaults(fn=cmd_menu)
    sub.add_parser("interactive", help="interactive CLI menu").set_defaults(fn=cmd_menu)

    p = sub.add_parser("import", help="import credentials from akun.txt into state")
    p.add_argument("--file", default=ACCOUNTS_FILE,
                   help=f"account list file, one email:password per line (default {ACCOUNTS_FILE})")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("harvest", help="login + approve + poll -> slk_ keys")
    p.add_argument("--email", required=True)
    p.add_argument("--password", default="",
                   help="account password (optional if already stored in state)")
    p.add_argument("--count", type=int, default=1, help="how many keys to mint")
    p.add_argument("--mode", choices=["both", "remote", "cli"], default="both",
                   help="approval path: remote RPC / manual web / both")
    p.add_argument("--tag", default="", help="client_name tag for the device request")
    p.set_defaults(fn=cmd_harvest)

    sub.add_parser("status", help="list harvested keys").set_defaults(fn=cmd_status)
    sub.add_parser("config", help="show 9router and tmpmail configuration").set_defaults(fn=cmd_config)
    sub.add_parser("sync-9router", help="sync harvested keys to 9router provider connections").set_defaults(fn=cmd_sync_9router)

    p = sub.add_parser("batch", help="run every account in akun.txt / state")
    p.add_argument("--file", default=ACCOUNTS_FILE,
                   help=f"account list, one email:password per line (default {ACCOUNTS_FILE})")
    p.add_argument("--stored", action="store_true",
                   help="run accounts already stored in state (bypasses file)")
    p.add_argument("--count", type=int, default=1, help="keys to mint per account")
    p.add_argument("--workers", type=int, default=0,
                   help="parallel accounts (0 = min(4, accounts))")
    p.add_argument("--mode", choices=["both", "remote", "cli"], default="both",
                   help="approval path: remote RPC / manual web / both")
    p.add_argument("--tag", default="", help="client_name tag for device requests")
    p.add_argument("--out", default="keys.txt",
                   help="dump all slk_ keys here ('' disables)")
    p.set_defaults(fn=cmd_batch)

    p = sub.add_parser("glogin", help="Google OAuth (PKCE) login -> mint keys")
    p.add_argument("--batch", action="store_true",
                   help="login all accounts in akun.txt sequentially via Camoufox")
    p.add_argument("--file", default=ACCOUNTS_FILE,
                   help=f"account list file for batch OAuth (default {ACCOUNTS_FILE})")
    p.add_argument("--email", default=None, help="single Google account email")
    p.add_argument("--password", default=None, help="single Google account password")
    p.add_argument("--count", type=int, default=1, help="how many keys to mint")
    p.add_argument("--mode", choices=["both", "remote", "cli"], default="both",
                   help="approval path: remote RPC / manual web / both")
    p.add_argument("--tag", default="", help="client_name tag for the device request")
    p.add_argument("--email-hint", default="google",
                   help="label if Google hides the email (state key prefix)")
    p.add_argument("--port", type=int, default=0,
                   help="local OAuth callback port (0 = auto)")
    p.set_defaults(fn=cmd_glogin)

    p = sub.add_parser("models", help="probe gateway /models with a key")
    p.add_argument("--key", required=True)
    p.set_defaults(fn=cmd_models)

    p = sub.add_parser("chat", help="one-shot gateway chat completion")
    p.add_argument("--key", required=True)
    p.add_argument("--model", default="deepseek-v4-flash")
    p.add_argument("--prompt", default="ping")
    p.add_argument("--max-tokens", type=int, default=32)
    p.set_defaults(fn=cmd_chat)


    args = ap.parse_args()
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print("\n[*] interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
