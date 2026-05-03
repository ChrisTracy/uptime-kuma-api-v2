#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Uptime Kuma HTTP Bridge — v2 compatible, raw socket.io, 2FA/TOTP support.
 
Install deps:
    pip3 install "python-socketio[client]" websocket-client pyotp --break-system-packages
 
.env keys:
    BRIDGE_HOST       default 127.0.0.1
    BRIDGE_PORT       default 9911
    BRIDGE_TOKEN      bearer token to protect this bridge (leave blank = no auth)
    KUMA_URL          e.g. http://127.0.0.1:3001
    KUMA_USERNAME     your Kuma username
    KUMA_PASSWORD     your Kuma password
    KUMA_2FA_SECRET   your TOTP secret (the base32 string from your authenticator
                      app setup — NOT the 6-digit code). Leave blank if no 2FA.
    KUMA_TIMEOUT      default 60
"""
 
import os
import sys
import json
import time
import logging
import traceback
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
 
# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("bridge")
 
try:
    import socketio
except ImportError:
    log.error("python-socketio client is required.")
    log.error("  pip3 install 'python-socketio[client]' websocket-client pyotp --break-system-packages")
    sys.exit(1)
 
try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    import subprocess
    log.warning("pyotp not found — installing automatically...")
    for cmd in [
        [sys.executable, "-m", "pip", "install", "pyotp", "--break-system-packages", "-q"],
        [sys.executable, "-m", "pip", "install", "pyotp", "-q"],
    ]:
        try:
            subprocess.check_call(cmd)
            import pyotp
            HAS_PYOTP = True
            log.info("pyotp installed successfully.")
            break
        except Exception:
            continue
    else:
        log.warning("Could not install pyotp automatically.")
        HAS_PYOTP = False
 
 
# ----------------------------
# Load .env
# ----------------------------
def load_env(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
 
 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_env(os.path.join(BASE_DIR, ".env"))
 
# ----------------------------
# Config
# ----------------------------
BRIDGE_HOST      = os.environ.get("BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT      = int(os.environ.get("BRIDGE_PORT", "9911"))
BRIDGE_TOKEN     = (os.environ.get("BRIDGE_TOKEN") or "").strip() or None
KUMA_URL         = (os.environ.get("KUMA_URL") or "http://127.0.0.1:3001").rstrip("/")
KUMA_USERNAME    = os.environ.get("KUMA_USERNAME")
KUMA_PASSWORD    = os.environ.get("KUMA_PASSWORD")
KUMA_2FA_SECRET  = (os.environ.get("KUMA_2FA_SECRET") or "").strip() or None
KUMA_TIMEOUT     = int(os.environ.get("KUMA_TIMEOUT", "60"))
 
if KUMA_2FA_SECRET and not HAS_PYOTP:
    log.error("KUMA_2FA_SECRET is set but pyotp could not be installed.")
    sys.exit(1)
 
 
def current_totp() -> str:
    return pyotp.TOTP(KUMA_2FA_SECRET).now()
 
 
# ----------------------------
# HTTP helpers
# ----------------------------
def _normalise_monitor(monitor: dict) -> dict:
    m = dict(monitor)
    if "notifications" in m:
        ids = m.pop("notifications")
        if isinstance(ids, list):
            m["notificationIDList"] = {str(i): True for i in ids}
        elif isinstance(ids, dict):
            m["notificationIDList"] = ids
    if "tags" in m:
        normalised = []
        for t in m["tags"]:
            if isinstance(t, int):
                normalised.append({"id": t, "value": ""})
            elif isinstance(t, str):
                normalised.append({"name": t})
            elif isinstance(t, dict):
                normalised.append({"id": t["id"], "value": t.get("value", "")} if "id" in t else t)
        m["tags"] = normalised
    return m
 
 
def send_json(h: BaseHTTPRequestHandler, code: int, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    h.send_response(code)
    h.send_header("Content-Type", "application/json; charset=utf-8")
    h.send_header("Content-Length", str(len(raw)))
    h.end_headers()
    h.wfile.write(raw)
 
 
def require_auth(h: BaseHTTPRequestHandler) -> bool:
    if not BRIDGE_TOKEN:
        return True
    auth = h.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        send_json(h, 401, {"ok": False, "error": "Missing Authorization: Bearer <token>"})
        return False
    if auth.split(" ", 1)[1].strip() != BRIDGE_TOKEN:
        send_json(h, 403, {"ok": False, "error": "Invalid token"})
        return False
    return True
 
 
def read_json(h: BaseHTTPRequestHandler) -> dict:
    length = int(h.headers.get("Content-Length", "0"))
    raw = h.rfile.read(length) if length > 0 else b"{}"
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise ValueError("Invalid JSON body")
 
 
# ----------------------------
# Kuma socket.io client
# ----------------------------
class KumaClient:
    def __init__(self):
        self.sio = socketio.Client(
            logger=False,
            engineio_logger=False,
            reconnection=False,
        )
        self._lock = threading.Lock()
        self._cache: dict = {}
        self._waiters: dict = {}
 
    def __enter__(self):
        for evt in ["monitorList", "heartbeatList", "tagList", "toastError", "info"]:
            self._register(evt)
 
        log.debug("Connecting to Kuma at %s", KUMA_URL)
        self.sio.connect(
            KUMA_URL,
            socketio_path="socket.io",
            wait=True,
            wait_timeout=KUMA_TIMEOUT,
            transports=["websocket", "polling"],
        )
        log.debug("Socket connected, logging in...")
        self._do_login()
        log.debug("Login complete. Cache keys so far: %s", list(self._cache.keys()))
        self._prime_waiter("monitorList")
        return self
 
    def __exit__(self, *_):
        try:
            self.sio.disconnect()
        except Exception:
            pass
 
    def _do_login(self):
        if not KUMA_USERNAME or not KUMA_PASSWORD:
            return
 
        result = self.sio.call(
            "login",
            {"username": KUMA_USERNAME, "password": KUMA_PASSWORD},
            timeout=KUMA_TIMEOUT,
        )
        log.debug("Login response: %s", result)
 
        if result and result.get("ok"):
            return
 
        if result and result.get("tokenRequired"):
            if not KUMA_2FA_SECRET:
                raise RuntimeError(
                    "Kuma requires 2FA but KUMA_2FA_SECRET is not set in your .env."
                )
            last_result = None
            for attempt in range(2):
                totp_code = current_totp()
                last_result = self.sio.call(
                    "login",
                    {"username": KUMA_USERNAME, "password": KUMA_PASSWORD, "token": totp_code},
                    timeout=KUMA_TIMEOUT,
                )
                log.debug("2FA login attempt %d response: %s", attempt + 1, last_result)
                if last_result and last_result.get("ok"):
                    return
                if attempt == 0:
                    wait = 30 - (int(time.time()) % 30) + 1
                    log.warning("2FA attempt 1 failed, waiting %ds for next TOTP window...", wait)
                    time.sleep(wait)
            raise RuntimeError(f"2FA login failed after 2 attempts. Last response: {last_result}.")
 
        raise RuntimeError(f"Login failed. Response: {result}.")
 
    # ---- internal plumbing ----
 
    def _register(self, event_name: str) -> None:
        @self.sio.on(event_name)
        def _handler(*args):
            data = args[0] if len(args) == 1 else (list(args) if args else None)
            log.debug("Socket event received: %s (type=%s, len=%s)",
                      event_name, type(data).__name__,
                      len(data) if isinstance(data, (dict, list)) else "n/a")
            with self._lock:
                self._cache[event_name] = data
                w = self._waiters.get(event_name)
                if w:
                    w["data"] = data
                    w["evt"].set()
 
    def _prime_waiter(self, event_name: str) -> None:
        with self._lock:
            if event_name not in self._waiters:
                self._waiters[event_name] = {"evt": threading.Event(), "data": None}
 
    def _wait(self, event_name: str, timeout: float = None):
        timeout = timeout or KUMA_TIMEOUT
        with self._lock:
            if event_name in self._cache:
                log.debug("_wait(%s): returning from cache immediately", event_name)
                return self._cache[event_name]
            if event_name not in self._waiters:
                self._waiters[event_name] = {"evt": threading.Event(), "data": None}
            w = self._waiters[event_name]
 
        log.debug("_wait(%s): blocking up to %ss for event...", event_name, timeout)
        ok = w["evt"].wait(timeout=timeout)
 
        with self._lock:
            data = self._waiters.pop(event_name, {}).get("data")
            if data is None:
                data = self._cache.get(event_name)
 
        if not ok and data is None:
            raise TimeoutError(
                f"Timed out after {timeout}s waiting for '{event_name}'. "
                f"Cache keys received so far: {list(self._cache.keys())}"
            )
        log.debug("_wait(%s): got data (type=%s, len=%s)",
                  event_name, type(data).__name__,
                  len(data) if isinstance(data, (dict, list)) else "n/a")
        return data
 
    # ---- public API ----
 
    def get_monitors(self) -> dict:
        log.debug("get_monitors: clearing cache and re-logging in to trigger fresh monitorList push")
        with self._lock:
            self._cache.pop("monitorList", None)
        self._prime_waiter("monitorList")
        self._do_login()
        result = self._wait("monitorList")
        log.info("get_monitors: returning %d monitors", len(result) if result else 0)
        return result or {}
 
    def find_monitor_by_url(self, url: str) -> dict | None:
        def _strip(u):
            return u.lower().lstrip("https://").lstrip("http://").rstrip("/")
 
        needle = _strip(url)
        log.debug("find_monitor_by_url: looking for %s", needle)
        monitors = self.get_monitors()
        for mid, m in monitors.items():
            if _strip(m.get("url") or "") == needle:
                log.debug("find_monitor_by_url: found id=%s", mid)
                return {"id": int(mid), **m}
        log.debug("find_monitor_by_url: not found")
        return None
 
    def add_monitor(self, monitor: dict) -> dict:
        defaults = {
            "type": "http",
            "name": "",
            "description": None,
            "url": "",
            "method": "GET",
            "hostname": None,
            "port": None,
            "maxretries": 3,
            "weight": 2000,
            "active": True,
            "timeout": 48,
            "interval": 60,
            "retryInterval": 60,
            "resendInterval": 0,
            "keyword": "",
            "invertKeyword": False,
            "expiryNotification": False,
            "ignoreTls": False,
            "upsideDown": False,
            "packetSize": 56,
            "maxredirects": 10,
            "accepted_statuscodes": ["200-299"],
            "accepted_statuscodes_json": '["200-299"]',
            "dns_resolve_type": "A",
            "dns_resolve_server": "1.1.1.1",
            "dns_last_result": None,
            "docker_container": "",
            "docker_host": None,
            "proxyId": None,
            "notificationIDList": {},
            "mqttTopic": "",
            "mqttSuccessMessage": "",
            "mqttCheckType": "keyword",
            "databaseQuery": None,
            "authMethod": None,
            "grpcUrl": None,
            "grpcProtobuf": None,
            "grpcMethod": None,
            "grpcServiceName": None,
            "grpcEnableTls": False,
            "radiusCalledStationId": None,
            "radiusCallingStationId": None,
            "game": None,
            "gamedigGivenPortOnly": True,
            "httpBodyEncoding": "json",
            "jsonPath": None,
            "expectedValue": None,
            "kafkaProducerTopic": None,
            "kafkaProducerBrokers": [],
            "kafkaProducerSsl": False,
            "kafkaProducerAllowAutoTopicCreation": False,
            "kafkaProducerMessage": None,
            "cacheBust": False,
            "remote_browser": None,
            "snmpOid": None,
            "jsonPathOperator": "==",
            "snmpVersion": "2c",
            "smtpSecurity": None,
            "rabbitmqNodes": None,
            "conditions": [],
            "ipFamily": None,
            "ping_numeric": True,
            "ping_count": 1,
            "ping_per_request_timeout": 2,
            "headers": None,
            "body": None,
            "grpcBody": None,
            "grpcMetadata": None,
            "basic_auth_user": None,
            "basic_auth_pass": None,
            "oauth_client_id": None,
            "oauth_client_secret": None,
            "oauth_token_url": None,
            "oauth_scopes": None,
            "oauth_audience": None,
            "oauth_auth_method": "client_secret_basic",
            "pushToken": None,
            "databaseConnectionString": None,
            "radiusUsername": None,
            "radiusPassword": None,
            "radiusSecret": None,
            "mqttUsername": "",
            "mqttPassword": "",
            "mqttWebsocketPath": None,
            "authWorkstation": None,
            "authDomain": None,
            "tlsCa": None,
            "tlsCert": None,
            "tlsKey": None,
            "kafkaProducerSaslOptions": {"mechanism": "None"},
            "rabbitmqUsername": None,
            "rabbitmqPassword": None,
        }
        payload = {**defaults, **monitor}
        tags = payload.pop("tags", None)
        log.debug("add_monitor: sending to Kuma: name=%s url=%s", payload.get("name"), payload.get("url"))
        result = self.sio.call("add", payload, timeout=KUMA_TIMEOUT)
        log.debug("add_monitor: result=%s", result)
        if result and not result.get("ok"):
            raise RuntimeError(f"add failed: {result.get('msg', result)}")
        if tags is not None:
            monitor_id = result.get("monitorID") if result else None
            if monitor_id:
                resolved_tags = [self._ensure_tag_id(t) for t in tags]
                self._apply_monitor_tags(monitor_id, resolved_tags, existing_tags=[])
        return result
 
    def edit_monitor(self, monitor_id: int, monitor: dict) -> dict:
        monitors = self.get_monitors()
        existing = monitors.get(str(monitor_id)) or monitors.get(monitor_id) or {}
        data = {**existing, **monitor}
        data["id"] = monitor_id
 
        raw_tags = data.pop("tags", None)
        resolved_tags = [self._ensure_tag_id(t) for t in raw_tags] if raw_tags is not None else None
 
        log.debug("edit_monitor: id=%s", monitor_id)
        result = self.sio.call("editMonitor", data, timeout=KUMA_TIMEOUT)
        log.debug("edit_monitor: result=%s", result)
        if result and not result.get("ok"):
            raise RuntimeError(f"editMonitor failed: {result.get('msg', result)}")
 
        if resolved_tags is not None:
            self._apply_monitor_tags(monitor_id, resolved_tags, existing_tags=existing.get("tags") or [])
        return result
 
    def _fetch_tags(self) -> list:
        result = self.sio.call("getTags", timeout=KUMA_TIMEOUT)
        log.debug("_fetch_tags: result type=%s", type(result).__name__)
        if isinstance(result, dict) and result.get("ok"):
            tags = result.get("tags") or []
        elif isinstance(result, list):
            tags = result
        else:
            tags = []
        with self._lock:
            self._cache["tagList"] = tags
        return tags
 
    def get_tags(self) -> list:
        raw = self._cache.get("tagList")
        if not raw:
            raw = self._fetch_tags()
        return raw if isinstance(raw, list) else list(raw.values())
 
    def _ensure_tag_id(self, tag) -> dict:
        if isinstance(tag, int):
            return {"id": tag, "value": ""}
        if isinstance(tag, str):
            tag = {"name": tag}
        if "id" in tag:
            return {"id": tag["id"], "value": tag.get("value", "")}
 
        name = tag.get("name", "")
        color = tag.get("color", "#ffffff")
 
        for existing in self.get_tags():
            if (existing.get("name") or "").lower() == name.lower():
                return {"id": existing["id"], "value": tag.get("value", "")}
 
        result = self.sio.call("addTag", {"name": name, "color": color}, timeout=KUMA_TIMEOUT)
        if not result or not result.get("ok"):
            raise RuntimeError(f"addTag failed for '{name}': {result}")
        new_tag = result["tag"]
        with self._lock:
            self._cache["tagList"] = (self._cache.get("tagList") or []) + [new_tag]
        return {"id": new_tag["id"], "value": tag.get("value", "")}
 
    def _apply_monitor_tags(self, monitor_id: int, resolved_tags: list, existing_tags: list) -> None:
        for tag in existing_tags:
            tag_id = tag.get("tagId") or tag.get("tag_id") or tag.get("id")
            if tag_id:
                self.sio.call("deleteMonitorTag", (tag_id, monitor_id, tag.get("value", "")), timeout=KUMA_TIMEOUT)
        for tag in resolved_tags:
            result = self.sio.call("addMonitorTag", (tag["id"], monitor_id, tag.get("value", "")), timeout=KUMA_TIMEOUT)
            if result and not result.get("ok"):
                raise RuntimeError(f"addMonitorTag failed: {result.get('msg', result)}")
 
    def set_monitor_tags(self, monitor_id: int, tags: list, replace: bool = False) -> dict:
        resolved = [self._ensure_tag_id(t) for t in tags]
        results = {"deleted": [], "added": []}
 
        if replace:
            monitors = self.get_monitors()
            existing = monitors.get(str(monitor_id)) or monitors.get(monitor_id) or {}
            for tag in existing.get("tags") or []:
                tag_id = tag.get("tagId") or tag.get("tag_id") or tag.get("id")
                if tag_id:
                    r = self.sio.call("deleteMonitorTag", (tag_id, monitor_id, tag.get("value", "")), timeout=KUMA_TIMEOUT)
                    results["deleted"].append({"tagId": tag_id, "result": r})
 
        for tag in resolved:
            r = self.sio.call("addMonitorTag", (tag["id"], monitor_id, tag.get("value", "")), timeout=KUMA_TIMEOUT)
            if r and not r.get("ok"):
                raise RuntimeError(f"addMonitorTag failed: {r.get('msg', r)}")
            results["added"].append({"tagId": tag["id"], "result": r})
 
        return results
 
    def remove_monitor_tags(self, monitor_id: int, tags: list) -> dict:
        resolved = {t["id"] for t in [self._ensure_tag_id(t) for t in tags]}
        monitors = self.get_monitors()
        existing = monitors.get(str(monitor_id)) or monitors.get(monitor_id) or {}
        results = {"deleted": []}
 
        for tag in existing.get("tags") or []:
            tag_id = tag.get("tagId") or tag.get("tag_id") or tag.get("id")
            if tag_id in resolved:
                r = self.sio.call("deleteMonitorTag", (tag_id, monitor_id, tag.get("value", "")), timeout=KUMA_TIMEOUT)
                results["deleted"].append({"tagId": tag_id, "result": r})
 
        return results
 
    def delete_monitor(self, monitor_id: int) -> dict:
        result = self.sio.call("deleteMonitor", monitor_id, timeout=KUMA_TIMEOUT)
        if result and not result.get("ok"):
            raise RuntimeError(f"deleteMonitor failed: {result.get('msg', result)}")
        return result
 
    def pause_monitor(self, monitor_id: int) -> dict:
        result = self.sio.call("pauseMonitor", monitor_id, timeout=KUMA_TIMEOUT)
        if result and not result.get("ok"):
            raise RuntimeError(f"pauseMonitor failed: {result.get('msg', result)}")
        return result
 
    def resume_monitor(self, monitor_id: int) -> dict:
        result = self.sio.call("resumeMonitor", monitor_id, timeout=KUMA_TIMEOUT)
        if result and not result.get("ok"):
            raise RuntimeError(f"resumeMonitor failed: {result.get('msg', result)}")
        return result
 
    def get_heartbeats(self, monitor_id: int) -> dict:
        hb_all = self._wait("heartbeatList")
        if isinstance(hb_all, dict):
            return hb_all.get(str(monitor_id)) or hb_all.get(monitor_id) or {}
        return hb_all
 
    def sniff_next_add(self, timeout: int = 60) -> dict:
        captured = {"data": None}
        evt = threading.Event()
 
        @self.sio.on("add")
        def _on_add(*args):
            captured["data"] = args[0] if len(args) == 1 else list(args)
            evt.set()
 
        evt.wait(timeout=timeout)
        return captured["data"]
 
 
# ----------------------------
# Persistent connection pool
# ----------------------------
class _Pool:
    def __init__(self):
        self._kc: KumaClient | None = None
        self._lock = threading.Lock()
 
    def _connect(self) -> KumaClient:
        kc = KumaClient()
        kc.__enter__()
        return kc
 
    def connect(self):
        with self._lock:
            self._kc = self._connect()
            log.info("Kuma connection established.")
 
    def get(self) -> KumaClient:
        with self._lock:
            if self._kc is None or not self._kc.sio.connected:
                log.warning("Kuma socket disconnected — reconnecting...")
                if self._kc is not None:
                    try:
                        self._kc.__exit__(None, None, None)
                    except Exception:
                        pass
                self._kc = self._connect()
            return self._kc
 
    def disconnect(self):
        with self._lock:
            if self._kc is not None:
                try:
                    self._kc.__exit__(None, None, None)
                except Exception:
                    pass
                self._kc = None
 
 
_pool = _Pool()
 
 
# ----------------------------
# HTTP handler
# ----------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug("HTTP %s", fmt % args)
 
    def do_GET(self):
        if not require_auth(self):
            return
        if self.path.rstrip("/") == "/health":
            send_json(self, 200, {
                "ok": True,
                "ts": int(time.time()),
                "kuma_url": KUMA_URL,
                "timeout": KUMA_TIMEOUT,
                "2fa": bool(KUMA_2FA_SECRET),
            })
        else:
            send_json(self, 404, {"ok": False, "error": "Not found"})
 
    def do_POST(self):
        if not require_auth(self):
            return
        path = self.path.rstrip("/")
        log.debug("POST %s", path)
        try:
            routes = {
                "/call":                 self._compat_call,
                "/monitors/list":        self._list,
                "/monitors/find":        self._find,
                "/tags/list":            self._tags_list,
                "/monitors/add":         self._add,
                "/monitors/edit":        self._edit,
                "/monitors/delete":      self._delete,
                "/monitors/status":      self._status,
                "/monitors/pause":       self._pause,
                "/monitors/resume":      self._resume,
                "/monitors/sniff":       self._sniff,
                "/monitors/tags/set":    self._tags_set,
                "/monitors/tags/delete": self._tags_delete,
            }
            fn = routes.get(path)
            if fn:
                fn()
            else:
                send_json(self, 404, {"ok": False, "error": f"Unknown endpoint: {path}"})
        except Exception as e:
            log.exception("Error handling %s", path)
            send_json(self, 500, {
                "ok": False,
                "error": str(e),
                "trace": traceback.format_exc(limit=15),
            })
 
    def _list(self):
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.get_monitors()})
 
    def _tags_list(self):
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.get_tags()})
 
    def _find(self):
        body = read_json(self)
        url = (body.get("url") or "").strip()
        if not url:
            send_json(self, 400, {"ok": False, "error": "'url' is required"})
            return
        kc = _pool.get()
        monitor = kc.find_monitor_by_url(url)
        if monitor is None:
            send_json(self, 404, {"ok": False, "error": f"No monitor found with url: {url}"})
            return
        send_json(self, 200, {"ok": True, "result": monitor})
 
    def _add(self):
        body = read_json(self)
        monitor = body.get("monitor")
        if not isinstance(monitor, dict) or not monitor:
            send_json(self, 400, {"ok": False, "error": "'monitor' must be a non-empty object"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.add_monitor(_normalise_monitor(monitor))})
 
    def _edit(self):
        body = read_json(self)
        mid = body.get("monitor_id")
        monitor = body.get("monitor")
        if not isinstance(mid, int):
            send_json(self, 400, {"ok": False, "error": "'monitor_id' must be an integer"})
            return
        if not isinstance(monitor, dict) or not monitor:
            send_json(self, 400, {"ok": False, "error": "'monitor' must be a non-empty object"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.edit_monitor(mid, _normalise_monitor(monitor))})
 
    def _delete(self):
        body = read_json(self)
        mid = body.get("monitor_id")
        if not isinstance(mid, int):
            send_json(self, 400, {"ok": False, "error": "'monitor_id' must be an integer"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.delete_monitor(mid)})
 
    def _status(self):
        body = read_json(self)
        mid = body.get("monitor_id")
        if not isinstance(mid, int):
            send_json(self, 400, {"ok": False, "error": "'monitor_id' must be an integer"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.get_heartbeats(mid)})
 
    def _pause(self):
        body = read_json(self)
        mid = body.get("monitor_id")
        if not isinstance(mid, int):
            send_json(self, 400, {"ok": False, "error": "'monitor_id' must be an integer"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.pause_monitor(mid)})
 
    def _resume(self):
        body = read_json(self)
        mid = body.get("monitor_id")
        if not isinstance(mid, int):
            send_json(self, 400, {"ok": False, "error": "'monitor_id' must be an integer"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.resume_monitor(mid)})
 
    def _tags_set(self):
        body = read_json(self)
        mid = body.get("monitor_id")
        tags = body.get("tags")
        replace = bool(body.get("replace", False))
        if not isinstance(mid, int):
            send_json(self, 400, {"ok": False, "error": "'monitor_id' must be an integer"})
            return
        if not isinstance(tags, list):
            send_json(self, 400, {"ok": False, "error": "'tags' must be an array"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.set_monitor_tags(mid, tags, replace=replace)})
 
    def _tags_delete(self):
        body = read_json(self)
        mid = body.get("monitor_id")
        tags = body.get("tags")
        if not isinstance(mid, int):
            send_json(self, 400, {"ok": False, "error": "'monitor_id' must be an integer"})
            return
        if not isinstance(tags, list):
            send_json(self, 400, {"ok": False, "error": "'tags' must be an array"})
            return
        kc = _pool.get()
        send_json(self, 200, {"ok": True, "result": kc.remove_monitor_tags(mid, tags)})
 
    def _sniff(self):
        body = read_json(self)
        timeout = int(body.get("timeout", 60))
        kc = _pool.get()
        payload = kc.sniff_next_add(timeout=timeout)
        if payload is None:
            send_json(self, 408, {"ok": False, "error": f"No add event seen within {timeout}s."})
            return
        send_json(self, 200, {"ok": True, "captured_payload": payload})
 
    def _compat_call(self):
        body   = read_json(self)
        method = body.get("method")
        args   = body.get("args") or []
        kwargs = body.get("kwargs") or {}
 
        if not method:
            send_json(self, 400, {"ok": False, "error": "Missing 'method'"})
            return
 
        def _int_id():
            mid = None
            if args and isinstance(args[0], int):
                mid = args[0]
            if mid is None:
                mid = kwargs.get("id") or kwargs.get("monitor_id") or body.get("monitor_id")
            if not isinstance(mid, int):
                raise ValueError("Missing or non-integer monitor_id / id")
            return mid
 
        kc = _pool.get()
        if method == "get_monitors":
            send_json(self, 200, {"ok": True, "result": kc.get_monitors()})
        elif method == "add_monitor":
            monitor = kwargs if kwargs else (body.get("monitor") or {})
            if not monitor:
                send_json(self, 400, {"ok": False, "error": "Missing monitor data"})
                return
            send_json(self, 200, {"ok": True, "result": kc.add_monitor(monitor)})
        elif method == "edit_monitor":
            monitor = kwargs if kwargs else (body.get("monitor") or {})
            send_json(self, 200, {"ok": True, "result": kc.edit_monitor(_int_id(), monitor)})
        elif method == "delete_monitor":
            send_json(self, 200, {"ok": True, "result": kc.delete_monitor(_int_id())})
        elif method == "pause_monitor":
            send_json(self, 200, {"ok": True, "result": kc.pause_monitor(_int_id())})
        elif method == "resume_monitor":
            send_json(self, 200, {"ok": True, "result": kc.resume_monitor(_int_id())})
        elif method in ("get_monitor_status", "get_heartbeats"):
            send_json(self, 200, {"ok": True, "result": kc.get_heartbeats(_int_id())})
        else:
            send_json(self, 400, {"ok": False, "error": f"Unsupported method: {method}"})
 
 
# ----------------------------
# Entry point
# ----------------------------
def main():
    log.info("Listening  : http://%s:%s", BRIDGE_HOST, BRIDGE_PORT)
    log.info("Kuma URL   : %s", KUMA_URL)
    log.info("Timeout    : %ss", KUMA_TIMEOUT)
    log.info("Auth token : %s", "set" if BRIDGE_TOKEN else "NONE (open access)")
    log.info("2FA        : %s", "enabled (pyotp)" if KUMA_2FA_SECRET else "disabled")
    _pool.connect()
    httpd = ThreadingHTTPServer((BRIDGE_HOST, BRIDGE_PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log.info("Shutting down...")
        httpd.shutdown()
        _pool.disconnect()
        log.info("Bye.")
 
 
if __name__ == "__main__":
    main()
