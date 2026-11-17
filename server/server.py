#!/usr/bin/env python3
"""KT közbenső FUTÁR/GTFS-RT proxy + flotta-gyorsítótár.

A BKK_API_KEY csak folyamat-környezetből olvasódik; soha nem kerül
naplóba, válaszba, fájlba vagy hibauzenetbe.
"""
from __future__ import annotations

import json
import math
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent

def _env_path(name: str, default: Path) -> Path:
    v = (os.environ.get(name) or "").strip()
    return Path(v) if v else default

DATA_DIR = _env_path("KT_DATA_DIR", ROOT / "data")
LOG_DIR = _env_path("KT_LOG_DIR", ROOT / "logs")
VAR_DIR = _env_path("KT_VAR_DIR", ROOT / "var")
TOKEN_PATH = _env_path("KT_CLIENT_TOKEN_FILE", ROOT / "client-token.txt")
DB_PATH = DATA_DIR / "fleet.sqlite"
SYNC_DB_PATH = DATA_DIR / "sync.sqlite"

FUTAR_BASE = "https://futar.bkk.hu/api/query/v1/ws/otp/api/where/"
GTFSRT_BASE = "https://go.bkk.hu/api/query/v1/ws/gtfs-rt/full/"
CENTER_LAT = 47.49700
CENTER_LON = 19.04000
FLEET_RADIUS_PREFIX = 100000  # m, Volán előtagok
FLEET_RADIUS_CITY = 20000     # m, szűretlen (ennél nagyobb LIMIT_EXCEEDED)
PREFIXES = ("STZ", "AAGL", "RVY", "MOS")

POLL_ACTIVE_SEC = int(os.environ.get("KT_POLL_ACTIVE", "10"))
POLL_IDLE_SEC = int(os.environ.get("KT_POLL_IDLE", "45"))
IDLE_AFTER_SEC = int(os.environ.get("KT_IDLE_AFTER", "120"))
MIN_GAP_SEC = 5
HISTORY_DAYS = int(os.environ.get("KT_HISTORY_DAYS", "7"))
PORT = int(os.environ.get("KT_PORT", "8787"))
BIND = os.environ.get("KT_BIND", "127.0.0.1")
UA = "kt-server/0.1 (VOLAN Agglo KT cache-proxy)"

TTL_DEFAULT = 20
TTL_BY_ENDPOINT = {
    "trip-details.json": 300,
    "arrivals-and-departures-for-stop.json": 15,
    "vehicles-for-location.json": 10,
    "vehicles-for-route.json": 15,
    "route-details.json": 300,
    "alert-search.json": 60,
    "references.json": 3600,
    "search.json": 60,
    "stops-for-location.json": 60,
    "vehicles.json": 10,
    "gtfs-rt": 60,
}

# Eszközszinkron (bejelentkezés nélkül): a kliens véletlen szinkron-azonosítója + a kliens token.
SYNC_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
SYNC_KEY_RE = re.compile(r"^[a-z0-9_]{1,40}$")
SYNC_PATH_RE = re.compile(r"/sync/[^/?#\s]+")
SYNC_MAX_BYTES = int(os.environ.get("KT_SYNC_MAX_BYTES", "262144"))   # egy dokumentum, JSON
SYNC_MAX_VALUE = int(os.environ.get("KT_SYNC_MAX_VALUE", "65536"))    # egy kulcs értéke
SYNC_MAX_KEYS = int(os.environ.get("KT_SYNC_MAX_KEYS", "80"))
SYNC_MAX_DOCS = int(os.environ.get("KT_SYNC_MAX_DOCS", "200"))
SYNC_MIN_GAP_SEC = float(os.environ.get("KT_SYNC_MIN_GAP", "1.0"))    # írás / azonosító
SERVER_FEATURES = ["futar", "gtfs-rt", "fleet", "history", "auth", "sync"]

SECRET_PARAM_RE = re.compile(r"(?i)(key|token|apikey|api_key)=[^&\s]*")
SAFE_EP_RE = re.compile(r"^[a-z0-9_\-]+\.(json|pb)$")
SAFE_RT_RE = re.compile(r"^[A-Za-z0-9_\-]+(?:\.pb)?$")


def now() -> float:
    return time.time()


def now_ms() -> int:
    return int(time.time() * 1000)


def redact(s: str) -> str:
    if not s:
        return s
    key = os.environ.get("BKK_API_KEY") or ""
    token = STATE.token if STATE else ""
    if key:
        s = s.replace(key, "[redacted]")
        s = s.replace(urllib.parse.quote(key, safe=""), "[redacted]")
    if token:
        s = s.replace(token, "[redacted]")
        s = s.replace(urllib.parse.quote(token, safe=""), "[redacted]")
    s = SECRET_PARAM_RE.sub(r"\1=[redacted]", s)
    s = SYNC_PATH_RE.sub("/sync/[id]", s)
    return s


def log(msg: str) -> None:
    line = time.strftime("%Y-%m-%d %H:%M:%S") + " " + redact(str(msg))
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass
    try:
        with open(LOG_DIR / "server.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def norm_plate(p: Optional[str]) -> str:
    return re.sub(r"[^A-Z0-9]", "", (p or "").upper())


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(min(1.0, a)))


def ensure_dirs() -> None:
    for d in (DATA_DIR, LOG_DIR, VAR_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


def is_mock() -> bool:
    if (os.environ.get("KT_MOCK") or "").strip().lower() in {"1", "true", "yes"}:
        return True
    k = os.environ.get("BKK_API_KEY") or ""
    return k.startswith("KTMOCK")


def load_or_create_token() -> str:
    env_tok = (os.environ.get("KT_CLIENT_TOKEN") or "").strip()
    if env_tok:
        return env_tok
    if TOKEN_PATH.exists():
        tok = TOKEN_PATH.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    if (os.environ.get("KT_TOKEN_REQUIRED") or "").strip().lower() in {"1", "true", "yes"}:
        raise RuntimeError("missing client token")
    tok = secrets.token_urlsafe(32)
    try:
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_PATH.write_text(tok + "\n", encoding="utf-8")
        TOKEN_PATH.chmod(0o600)
    except OSError:
        pass
    return tok


def mock_futar_json(endpoint: str, params: dict[str, list[str]]) -> dict:
    """KTMOCK: helyi ál-FUTÁR válasz, nincs kimenő BKK-hívás."""
    now_i = now_ms()
    prefixes = list(PREFIXES)
    vehicles = []
    trips: dict[str, Any] = {}
    routes: dict[str, Any] = {}
    stops: dict[str, Any] = {}
    for i, px in enumerate(prefixes):
        plate = "%s%03d" % (px, 100 + i)
        tid = "BKK_MOCKTRIP_%s" % px
        rid = "BKK_0%d20" % (i + 1)
        lat = CENTER_LAT + 0.01 * i
        lon = CENTER_LON + 0.01 * i
        vehicles.append(
            {
                "vehicleId": "mock:%s" % plate,
                "licensePlate": plate,
                "label": plate,
                "location": {"lat": lat, "lon": lon},
                "bearing": 45 * i,
                "tripId": tid,
                "routeId": rid,
                "stopId": "BKK_MOCKSTOP_%s" % px,
                "stopSequence": 1,
                "lastUpdateTime": now_i,
                "status": "IN_TRANSIT_TO",
            }
        )
        trips[tid] = {
            "id": tid,
            "routeId": rid,
            "tripHeadsign": "Mock végállomás %s" % px,
            "blockId": "D20900_02%02d_1_3" % (i + 1),
            "serviceId": "S1",
        }
        routes[rid] = {
            "id": rid,
            "shortName": ["22", "22A", "116", "188"][i % 4],
            "type": "BUS",
            "color": "3D8BFF",
            "textColor": "FFFFFF",
        }
        sid = "BKK_MOCKSTOP_%s" % px
        stops[sid] = {"id": sid, "name": "Mock megálló %s" % px, "lat": lat, "lon": lon}
    q = (first(params, "query") or "").strip()
    if q:
        qn = norm_plate(q)
        vehicles = [v for v in vehicles if norm_plate(v.get("licensePlate")).startswith(qn) or norm_plate(v.get("licensePlate")) == qn]
    body: dict[str, Any] = {
        "currentTime": now_i,
        "version": 3,
        "status": "OK",
        "code": 200,
        "text": "OK",
        "data": {"limitExceeded": False, "list": vehicles, "references": {"trips": trips, "routes": routes, "stops": stops}},
    }
    if endpoint == "trip-details.json":
        tid = first(params, "tripId") or "BKK_MOCKTRIP_AAGL"
        st = []
        for k in range(4):
            sid = "BKK_MOCKSTOP_%d" % k
            stops[sid] = {"id": sid, "name": "Mock megálló %d" % k, "lat": CENTER_LAT, "lon": CENTER_LON}
            t = int(now()) + k * 300
            st.append({"stopId": sid, "arrivalTime": t, "departureTime": t, "stopSequence": k})
        body["data"] = {
            "entry": {"tripId": tid, "serviceDate": time.strftime("%Y%m%d"), "stopTimes": st, "vehicle": None},
            "references": {"stops": stops, "trips": trips, "routes": routes},
        }
    elif endpoint == "arrivals-and-departures-for-stop.json":
        body["data"] = {
            "entry": {"stopId": first(params, "stopId"), "arrivalsAndDepartures": []},
            "limitExceeded": False,
            "references": {"trips": trips, "routes": routes, "stops": stops},
        }
    return body


def cache_key(kind: str, endpoint: str, params: dict[str, list[str]]) -> str:
    items = []
    for k in sorted(params):
        if k.lower() in {"key", "token", "apikey", "api_key", "_", "cachebust"}:
            continue
        vals = sorted(params[k])
        items.append(k + "=" + ",".join(vals))
    return kind + "|" + endpoint + "|" + "&".join(items)


def parse_qs_multi(qs: str) -> dict[str, list[str]]:
    raw = urllib.parse.parse_qs(qs, keep_blank_values=True)
    return {k: [str(x) for x in v] for k, v in raw.items()}


def first(params: dict[str, list[str]], name: str, default: Optional[str] = None) -> Optional[str]:
    v = params.get(name)
    return v[0] if v else default


class Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.bkk: dict[str, int] = defaultdict(int)
        self.client: dict[str, int] = defaultdict(int)
        self.cache_hit = 0
        self.cache_stale = 0
        self.cache_miss = 0
        self.inflight_join = 0
        self.limit_exceeded = 0
        self.clients: dict[str, float] = {}
        self.minute_log: deque[dict[str, Any]] = deque(maxlen=180)

    def add_bkk(self, endpoint: str) -> None:
        with self.lock:
            self.bkk[endpoint] += 1

    def add_client(self, path: str, client_id: str) -> None:
        with self.lock:
            self.client[path] += 1
            self.clients[client_id] = now()

    def add_cache(self, kind: str) -> None:
        with self.lock:
            if kind == "hit":
                self.cache_hit += 1
            elif kind == "stale":
                self.cache_stale += 1
            elif kind == "inflight":
                self.inflight_join += 1
            else:
                self.cache_miss += 1

    def add_limit(self) -> None:
        with self.lock:
            self.limit_exceeded += 1

    def snapshot_and_reset(self) -> dict[str, Any]:
        with self.lock:
            bkk = dict(self.bkk)
            client = dict(self.client)
            hit = self.cache_hit
            stale = self.cache_stale
            miss = self.cache_miss
            infl = self.inflight_join
            lim = self.limit_exceeded
            unique = sum(1 for t in self.clients.values() if now() - t < 60)
            unique_2m = sum(1 for t in self.clients.values() if now() - t < 120)
            self.bkk = defaultdict(int)
            self.client = defaultdict(int)
            self.cache_hit = self.cache_stale = self.cache_miss = 0
            self.inflight_join = 0
            self.limit_exceeded = 0
        bkk_n = sum(bkk.values())
        client_n = sum(client.values())
        looked = hit + stale + miss
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "bkk_per_min": bkk_n,
            "bkk_by_endpoint": bkk,
            "client_per_min": client_n,
            "client_by_path": client,
            "cache_hit": hit,
            "cache_stale": stale,
            "cache_miss": miss,
            "inflight_join": infl,
            "cache_hit_ratio": (round((hit + stale) / looked, 3) if looked else None),
            "unique_clients_60s": unique,
            "unique_clients_120s": unique_2m,
            "limit_exceeded": lim,
        }
        with self.lock:
            self.minute_log.append(rec)
        return rec

    def recent(self, n: int = 30) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.minute_log)[-n:]


class Backoff:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.until = 0.0
        self.level = 0
        self.events = 0
        self.last_event: Optional[str] = None

    def hit(self, why: str = "LIMIT_EXCEEDED") -> float:
        with self.lock:
            delay = min(900, 30 * (2 ** self.level))
            self.level = min(self.level + 1, 5)
            self.until = now() + delay
            self.events += 1
            self.last_event = time.strftime("%Y-%m-%dT%H:%M:%S") + " " + why
            return delay

    def success(self) -> None:
        with self.lock:
            self.level = 0
            self.until = 0.0

    def remaining(self) -> float:
        with self.lock:
            return max(0.0, self.until - now())

    def active(self) -> bool:
        return self.remaining() > 0

    def info(self) -> dict[str, Any]:
        with self.lock:
            return {
                "active": self.until > now(),
                "remaining_sec": max(0, int(self.until - now())),
                "level": self.level,
                "events": self.events,
                "last_event": self.last_event,
            }


class CacheEntry:
    __slots__ = ("kind", "payload", "content_type", "fetched_at", "ttl", "status")

    def __init__(
        self,
        kind: str,
        payload: Any,
        content_type: str,
        fetched_at: float,
        ttl: float,
        status: int = 200,
    ) -> None:
        self.kind = kind
        self.payload = payload
        self.content_type = content_type
        self.fetched_at = fetched_at
        self.ttl = ttl
        self.status = status

    def age(self) -> float:
        return now() - self.fetched_at

    def fresh(self) -> bool:
        return self.age() <= self.ttl


class FleetCache:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.list: list[dict[str, Any]] = []
        self.refs: dict[str, Any] = {"trips": {}, "routes": {}, "stops": {}}
        self.fetched_at: float = 0.0
        self.current_time: Optional[int] = None
        self.ok = False
        self.notes: list[str] = []
        self.mode: str = ""
        self.bkk_calls: int = 0

    def set(
        self,
        lst: list[dict[str, Any]],
        refs: dict[str, Any],
        current_time: Optional[int],
        mode: str,
        notes: list[str],
        bkk_calls: int,
    ) -> None:
        with self.lock:
            self.list = lst
            self.refs = refs
            self.current_time = current_time
            self.fetched_at = now()
            self.ok = True
            self.mode = mode
            self.notes = notes
            self.bkk_calls = bkk_calls

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "list": self.list,
                "refs": self.refs,
                "fetched_at": self.fetched_at,
                "current_time": self.current_time,
                "ok": self.ok,
                "mode": self.mode,
                "notes": list(self.notes),
                "age": (now() - self.fetched_at) if self.fetched_at else None,
            }


class State:
    def __init__(self) -> None:
        self.token = load_or_create_token()
        self.api_key = os.environ.get("BKK_API_KEY") or ""
        self.stats = Stats()
        self.backoff = Backoff()
        self.fleet = FleetCache()
        self.cache: dict[str, CacheEntry] = {}
        self.cache_lock = threading.Lock()
        self.inflight: dict[str, threading.Event] = {}
        self.inflight_box: dict[str, Any] = {}
        self.inflight_lock = threading.Lock()
        self.last_bkk: dict[str, float] = {}
        self.last_client_at = 0.0
        self.client_lock = threading.Lock()
        self.db_lock = threading.Lock()
        self.stop = threading.Event()
        self.poll_interval = POLL_IDLE_SEC
        self.started_at = now()
        self.db = self._open_db()

    def _open_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fleet_history (
              plate TEXT NOT NULL,
              ts INTEGER NOT NULL,
              lat REAL,
              lon REAL,
              route TEXT,
              trip TEXT,
              heading REAL,
              vehicle_id TEXT,
              PRIMARY KEY (plate, ts)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hist_plate_ts ON fleet_history(plate, ts)")
        conn.commit()
        return conn

    def mark_client(self) -> None:
        with self.client_lock:
            self.last_client_at = now()

    def last_client_age(self) -> float:
        with self.client_lock:
            if not self.last_client_at:
                return 1e9
            return now() - self.last_client_at

    def desired_poll(self) -> int:
        return POLL_ACTIVE_SEC if self.last_client_age() <= IDLE_AFTER_SEC else POLL_IDLE_SEC


class SyncError(Exception):
    def __init__(self, code: int, status: str, text: str) -> None:
        super().__init__(text)
        self.code = code
        self.status = status
        self.text = text


class SyncStore:
    """Kulcsonkénti last-write-wins tár: {kulcs: {"v": str|None, "ts": ms}}. Külön SQLite-fájl."""

    def __init__(self, path: Path) -> None:
        self.lock = threading.Lock()
        self.last_put: dict[str, float] = {}
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS sync_doc (id TEXT PRIMARY KEY, data TEXT NOT NULL, rev INTEGER NOT NULL, "
            "updated INTEGER NOT NULL, size INTEGER NOT NULL)"
        )
        self.conn.commit()

    def _load(self, sid: str) -> tuple[int, dict[str, Any], int]:
        row = self.conn.execute("SELECT data, rev, updated FROM sync_doc WHERE id=?", (sid,)).fetchone()
        if not row:
            return 0, {}, 0
        try:
            data = json.loads(row[0])
        except Exception:
            data = {}
        return int(row[1]), data if isinstance(data, dict) else {}, int(row[2])

    def get(self, sid: str) -> tuple[int, dict[str, Any], int]:
        with self.lock:
            return self._load(sid)

    def merge(self, sid: str, incoming: Any) -> tuple[int, dict[str, Any], list[str]]:
        if not isinstance(incoming, dict):
            raise SyncError(400, "ERROR", "data must be an object")
        t_now = now_ms()
        with self.lock:
            last = self.last_put.get(sid, 0.0)
            if now() - last < SYNC_MIN_GAP_SEC:
                raise SyncError(429, "RATE_LIMIT", "too many writes")
            rev, data, _ = self._load(sid)
            if rev == 0:
                n = self.conn.execute("SELECT COUNT(*) FROM sync_doc").fetchone()[0]
                if n >= SYNC_MAX_DOCS:
                    raise SyncError(507, "FULL", "too many sync documents")
            changed: list[str] = []
            for k, e in incoming.items():
                if not isinstance(k, str) or not SYNC_KEY_RE.match(k):
                    raise SyncError(400, "ERROR", "invalid key")
                if not isinstance(e, dict):
                    raise SyncError(400, "ERROR", "invalid entry")
                v = e.get("v")
                ts = e.get("ts")
                if v is not None and not isinstance(v, str):
                    raise SyncError(400, "ERROR", "value must be string or null")
                if isinstance(ts, bool) or not isinstance(ts, (int, float)):
                    raise SyncError(400, "ERROR", "ts must be a number")
                if v is not None and len(v.encode("utf-8")) > SYNC_MAX_VALUE:
                    raise SyncError(413, "TOO_LARGE", "value too large")
                ts = int(min(ts, t_now + 5000))  # jövőbeli időbélyeg nem zárhatja le a kulcsot
                cur = data.get(k)
                cur_ts = int(cur.get("ts") or 0) if isinstance(cur, dict) else -1
                if ts > cur_ts:
                    if isinstance(cur, dict) and cur.get("v") == v:
                        data[k] = {"v": v, "ts": ts}
                        continue
                    data[k] = {"v": v, "ts": ts}
                    changed.append(k)
            if len(data) > SYNC_MAX_KEYS:
                raise SyncError(413, "TOO_LARGE", "too many keys")
            raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            if len(raw.encode("utf-8")) > SYNC_MAX_BYTES:
                raise SyncError(413, "TOO_LARGE", "document too large")
            self.last_put[sid] = now()
            if len(self.last_put) > 2000:
                for x in sorted(self.last_put, key=self.last_put.get)[:1000]:
                    self.last_put.pop(x, None)
            if changed or rev == 0:
                rev += 1
            self.conn.execute(
                "INSERT INTO sync_doc(id,data,rev,updated,size) VALUES(?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET data=excluded.data, rev=excluded.rev, updated=excluded.updated, size=excluded.size",
                (sid, raw, rev, t_now, len(raw)),
            )
            self.conn.commit()
            return rev, data, changed


STATE: Optional[State] = None
SYNC: Optional[SyncStore] = None


def bkk_get_json(endpoint: str, params: dict[str, list[str]]) -> tuple[int, Any]:
    """Call FUTÁR. Never logs the URL with the key."""
    assert STATE is not None
    if not STATE.api_key:
        raise RuntimeError("missing BKK_API_KEY")
    if is_mock():
        STATE.stats.add_bkk(endpoint)
        with STATE.cache_lock:
            STATE.last_bkk[cache_key("futar", endpoint, params)] = now()
        return 200, mock_futar_json(endpoint, params)
    if STATE.backoff.active():
        raise RuntimeError("backoff")
    q: list[tuple[str, str]] = []
    for k, vals in params.items():
        if k.lower() in {"key", "token", "apikey", "api_key"}:
            continue
        for v in vals:
            q.append((k, v))
    q.append(("key", STATE.api_key))
    url = FUTAR_BASE + endpoint + "?" + urllib.parse.urlencode(q)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    STATE.stats.add_bkk(endpoint)
    with STATE.cache_lock:
        STATE.last_bkk[cache_key("futar", endpoint, params)] = now()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            http = getattr(resp, "status", 200)
    except urllib.error.HTTPError as e:
        raw = e.read() or b""
        http = e.code
        try:
            body = json.loads(raw)
        except Exception:
            body = {"status": "HTTP_ERROR", "code": http, "text": "non-json error"}
        if is_limit_exceeded(http, body):
            delay = STATE.backoff.hit("LIMIT_EXCEEDED %s %s" % (endpoint, http))
            STATE.stats.add_limit()
            log("LIMIT_EXCEEDED endpoint=%s http=%s backoff=%ss" % (endpoint, http, int(delay)))
        else:
            log("bkk_http_error endpoint=%s http=%s status=%s" % (endpoint, http, (body or {}).get("status")))
        return http, body
    except Exception as e:
        log("bkk_error endpoint=%s err=%s" % (endpoint, type(e).__name__))
        raise
    try:
        body = json.loads(raw)
    except Exception:
        raise RuntimeError("bkk_non_json endpoint=%s" % endpoint)
    if is_limit_exceeded(http, body):
        delay = STATE.backoff.hit("LIMIT_EXCEEDED %s body" % endpoint)
        STATE.stats.add_limit()
        log("LIMIT_EXCEEDED endpoint=%s http=%s status=%s backoff=%ss" % (endpoint, http, body.get("status"), int(delay)))
    else:
        if body.get("status") == "OK":
            STATE.backoff.success()
    return http, body


def bkk_get_bytes(url_base: str, name: str) -> tuple[int, bytes, str]:
    assert STATE is not None
    if not STATE.api_key:
        raise RuntimeError("missing BKK_API_KEY")
    filename = name if name.endswith(".pb") else name + ".pb"
    if is_mock():
        STATE.stats.add_bkk("gtfs-rt:" + filename)
        with STATE.cache_lock:
            STATE.last_bkk[cache_key("gtfs-rt", filename, {})] = now()
        return 200, b"", "application/octet-stream"
    if STATE.backoff.active():
        raise RuntimeError("backoff")
    url = url_base + filename + "?" + urllib.parse.urlencode({"key": STATE.api_key})
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/octet-stream"})
    ep = "gtfs-rt:" + filename
    STATE.stats.add_bkk(ep)
    with STATE.cache_lock:
        STATE.last_bkk[cache_key("gtfs-rt", filename, {})] = now()
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read()
            http = getattr(resp, "status", 200)
            ctype = resp.headers.get("Content-Type") or "application/octet-stream"
            STATE.backoff.success()
            return http, raw, ctype
    except urllib.error.HTTPError as e:
        raw = e.read() or b""
        if e.code in (400, 429) or b"LIMIT_EXCEEDED" in raw:
            delay = STATE.backoff.hit("LIMIT_EXCEEDED gtfs-rt %s" % e.code)
            STATE.stats.add_limit()
            log("LIMIT_EXCEEDED gtfs-rt http=%s backoff=%ss" % (e.code, int(delay)))
        else:
            log("bkk_gtfsrt_http endpoint=%s http=%s" % (filename, e.code))
        return e.code, raw, "application/octet-stream"


def is_limit_exceeded(http: int, body: Any) -> bool:
    if http == 429:
        return True
    if isinstance(body, dict):
        st = str(body.get("status") or "")
        tx = str(body.get("text") or "")
        if "LIMIT_EXCEEDED" in st.upper() or "limit exceeded" in tx.lower():
            return True
    return False


def respect_min_gap(ck: str) -> None:
    assert STATE is not None
    with STATE.cache_lock:
        last = STATE.last_bkk.get(ck, 0.0)
    wait = MIN_GAP_SEC - (now() - last)
    if wait > 0:
        time.sleep(wait)


def cache_get(ck: str) -> Optional[CacheEntry]:
    assert STATE is not None
    with STATE.cache_lock:
        return STATE.cache.get(ck)


def cache_put(ck: str, entry: CacheEntry) -> None:
    assert STATE is not None
    with STATE.cache_lock:
        STATE.cache[ck] = entry
        if len(STATE.cache) > 4000:
            # drop oldest half
            items = sorted(STATE.cache.items(), key=lambda kv: kv[1].fetched_at)
            for k, _ in items[: len(items) // 2]:
                STATE.cache.pop(k, None)


def inflight_join_or_begin(ck: str) -> Optional[threading.Event]:
    """Return existing Event to wait on, or None if this caller should fetch."""
    assert STATE is not None
    with STATE.inflight_lock:
        ev = STATE.inflight.get(ck)
        if ev is not None:
            return ev
        ev = threading.Event()
        STATE.inflight[ck] = ev
        return None


def inflight_finish(ck: str, result: Any) -> None:
    assert STATE is not None
    with STATE.inflight_lock:
        STATE.inflight_box[ck] = result
        ev = STATE.inflight.pop(ck, None)
    if ev is not None:
        ev.set()
    def _cleanup() -> None:
        time.sleep(1)
        with STATE.inflight_lock:
            STATE.inflight_box.pop(ck, None)
    threading.Thread(target=_cleanup, daemon=True).start()


def inflight_wait(ev: threading.Event, ck: str, timeout: float = 35.0) -> Any:
    ev.wait(timeout)
    assert STATE is not None
    with STATE.inflight_lock:
        return STATE.inflight_box.get(ck)


def fetch_futar_cached(endpoint: str, params: dict[str, list[str]]) -> tuple[int, Any, str, bool]:
    """Return (http, body, cache_status, stale). cache_status in hit/stale/miss/inflight."""
    assert STATE is not None
    ttl = TTL_BY_ENDPOINT.get(endpoint, TTL_DEFAULT)
    ck = cache_key("futar", endpoint, params)
    ent = cache_get(ck)
    if ent and ent.fresh():
        STATE.stats.add_cache("hit")
        return ent.status, ent.payload, "hit", False
    if STATE.backoff.active() and ent:
        STATE.stats.add_cache("stale")
        return ent.status, ent.payload, "stale", True
    ev = inflight_join_or_begin(ck)
    if ev is not None:
        STATE.stats.add_cache("inflight")
        boxed = inflight_wait(ev, ck)
        if boxed is not None:
            http, body, st, stale = boxed
            return http, body, st if st == "miss" else "inflight", stale
        if ent:
            STATE.stats.add_cache("stale")
            return ent.status, ent.payload, "stale", True
        return 503, {"status": "ERROR", "text": "in-flight timeout"}, "miss", True
    try:
        if ent and not ent.fresh():
            # TTL lejárt, de 5 mp-es rés: a régi adat mehet, ha a résen belül vagyunk
            with STATE.cache_lock:
                last = STATE.last_bkk.get(ck, 0.0)
            if last and now() - last < MIN_GAP_SEC:
                STATE.stats.add_cache("hit")
                inflight_finish(ck, (ent.status, ent.payload, "hit", False))
                return ent.status, ent.payload, "hit", False
        respect_min_gap(ck)
        if STATE.backoff.active():
            if ent:
                STATE.stats.add_cache("stale")
                inflight_finish(ck, (ent.status, ent.payload, "stale", True))
                return ent.status, ent.payload, "stale", True
            inflight_finish(ck, (503, {"status": "BACKOFF", "text": "BKK LIMIT_EXCEEDED backoff"}, "miss", True))
            return 503, {"status": "BACKOFF", "text": "BKK LIMIT_EXCEEDED backoff"}, "miss", True
        STATE.stats.add_cache("miss")
        http, body = bkk_get_json(endpoint, params)
        stale = is_limit_exceeded(http, body)
        if not stale and http < 500:
            cache_put(ck, CacheEntry("json", body, "application/json", now(), ttl, http))
        elif ent and stale:
            inflight_finish(ck, (ent.status, ent.payload, "stale", True))
            return ent.status, ent.payload, "stale", True
        inflight_finish(ck, (http, body, "miss", stale))
        return http, body, "miss", stale
    except Exception as e:
        log("fetch_futar_failed endpoint=%s err=%s" % (endpoint, type(e).__name__))
        if ent:
            STATE.stats.add_cache("stale")
            inflight_finish(ck, (ent.status, ent.payload, "stale", True))
            return ent.status, ent.payload, "stale", True
        body = {"status": "ERROR", "text": "upstream error"}
        inflight_finish(ck, (502, body, "miss", True))
        return 502, body, "miss", True


def merge_refs(dst: dict[str, Any], src: Optional[dict[str, Any]]) -> None:
    if not src:
        return
    for group in ("trips", "routes", "stops", "agencies"):
        if group in src and isinstance(src[group], dict):
            dst.setdefault(group, {}).update(src[group])


def uniq_vehicles(lst: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for v in lst:
        p = norm_plate(v.get("licensePlate"))
        key = p or str(v.get("vehicleId") or "")
        if not key:
            key = "anon-%s" % id(v)
        prev = seen.get(key)
        if prev is None:
            seen[key] = v
            order.append(key)
            continue
        better = False
        if bool(v.get("tripId")) and not bool(prev.get("tripId")):
            better = True
        elif bool(v.get("tripId")) == bool(prev.get("tripId")) and (v.get("lastUpdateTime") or 0) > (prev.get("lastUpdateTime") or 0):
            better = True
        if better:
            seen[key] = v
    return [seen[k] for k in order]


def fetch_fleet_once() -> bool:
    """Minimális számú kéréssel frissíti a flotta-gyorsítótárat. 4 előtag × 100 km.

    Közvetlenül a BKK-t hívja (a 10 mp-es HTTP-tárat kihagyja), de a választ
    berakja a tárba, hogy a kliens ugyanarra a prefix-kérésre ne hívjon újra.
    """
    assert STATE is not None
    if STATE.backoff.active():
        log("fleet_skip backoff remaining=%ss" % int(STATE.backoff.remaining()))
        return False
    notes: list[str] = []
    merged: list[dict[str, Any]] = []
    refs: dict[str, Any] = {"trips": {}, "routes": {}, "stops": {}}
    current_time = None
    calls = 0
    ok_any = False
    ttl = TTL_BY_ENDPOINT["vehicles-for-location.json"]
    for px in PREFIXES:
        if STATE.backoff.active():
            notes.append("%s: skipped backoff" % px)
            break
        params = {
            "lat": [str(CENTER_LAT)],
            "lon": [str(CENTER_LON)],
            "radius": [str(FLEET_RADIUS_PREFIX)],
            "query": [px],
            "includeReferences": ["trips,routes"],
        }
        ck = cache_key("futar", "vehicles-for-location.json", params)
        respect_min_gap(ck)
        try:
            http, body = bkk_get_json("vehicles-for-location.json", params)
            calls += 1
        except Exception as e:
            notes.append("%s: %s" % (px, type(e).__name__))
            if STATE.backoff.active():
                break
            continue
        if not isinstance(body, dict):
            notes.append("%s: invalid body" % px)
            continue
        if is_limit_exceeded(http, body):
            notes.append("%s: %s" % (px, body.get("status") or http))
            # utolsó jó tárat nem írjuk felül hibával
            break
        if http != 200 or body.get("status") not in (None, "OK"):
            notes.append("%s: http=%s status=%s" % (px, http, body.get("status")))
            continue
        cache_put(ck, CacheEntry("json", body, "application/json", now(), ttl, http))
        data = body.get("data") or {}
        if data.get("limitExceeded"):
            notes.append("%s: data.limitExceeded (truncated)" % px)
        lst = data.get("list") or []
        for v in lst:
            p = norm_plate(v.get("licensePlate"))
            if p and p.startswith(px):
                merged.append(v)
            elif not p:
                merged.append(v)
        merge_refs(refs, data.get("references"))
        if body.get("currentTime"):
            current_time = body.get("currentTime")
        ok_any = True
    if not ok_any:
        log("fleet_refresh failed notes=%s" % ";".join(notes)[:200])
        return False
    uniq = uniq_vehicles(merged)
    STATE.fleet.set(uniq, refs, current_time, "prefixes-100km", notes, calls)
    store_history(uniq, refs)
    log(
        "fleet_refresh ok n=%s bkk_calls=%s notes=%s"
        % (len(uniq), calls, ";".join(notes)[:160] or "-")
    )
    return True


def route_name(v: dict[str, Any], refs: dict[str, Any]) -> str:
    rid = v.get("routeId")
    routes = (refs or {}).get("routes") or {}
    r = routes.get(rid) if rid else None
    if isinstance(r, dict):
        return r.get("shortName") or rid or ""
    return rid or ""


def store_history(lst: list[dict[str, Any]], refs: dict[str, Any]) -> None:
    assert STATE is not None
    ts = now_ms()
    rows = []
    for v in lst:
        plate = norm_plate(v.get("licensePlate"))
        if not plate:
            continue
        loc = v.get("location") or {}
        try:
            lat = float(loc.get("lat"))
            lon = float(loc.get("lon"))
        except (TypeError, ValueError):
            continue
        rows.append(
            (
                plate,
                ts,
                lat,
                lon,
                route_name(v, refs),
                v.get("tripId") or "",
                v.get("bearing"),
                v.get("vehicleId") or "",
            )
        )
    if not rows:
        return
    try:
        with STATE.db_lock:
            # skip if last point for plate is essentially identical
            last = {
                r[0]: r
                for r in STATE.db.execute(
                    "SELECT plate, ts, lat, lon, trip FROM fleet_history "
                    "WHERE ts=(SELECT MAX(ts) FROM fleet_history h2 WHERE h2.plate=fleet_history.plate)"
                ).fetchall()
            } if False else None
            # cheaper: per-plate last via a small query in loop would be slow;
            # use a temp map from a single query of latest ts per plate among this batch
            plates = [r[0] for r in rows]
            qmarks = ",".join("?" * len(plates))
            latest = {}
            if plates:
                cur = STATE.db.execute(
                    "SELECT plate, MAX(ts) FROM fleet_history WHERE plate IN (%s) GROUP BY plate" % qmarks,
                    plates,
                )
                mx = dict(cur.fetchall())
                if mx:
                    # fetch those rows
                    cond = " OR ".join(["(plate=? AND ts=?)"] * len(mx))
                    args: list[Any] = []
                    for p, t in mx.items():
                        args.extend([p, t])
                    for r in STATE.db.execute(
                        "SELECT plate, ts, lat, lon, trip FROM fleet_history WHERE " + cond, args
                    ):
                        latest[r[0]] = r
            to_ins = []
            for r in rows:
                prev = latest.get(r[0])
                if prev:
                    try:
                        if abs(prev[2] - r[2]) < 1e-5 and abs(prev[3] - r[3]) < 1e-5 and (prev[4] or "") == (r[5] or ""):
                            continue
                    except Exception:
                        pass
                to_ins.append(r)
            if to_ins:
                STATE.db.executemany(
                    "INSERT OR IGNORE INTO fleet_history(plate,ts,lat,lon,route,trip,heading,vehicle_id) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    to_ins,
                )
                STATE.db.commit()
    except Exception as e:
        log("history_write_error err=%s" % type(e).__name__)


def prune_history() -> None:
    assert STATE is not None
    cutoff = now_ms() - HISTORY_DAYS * 24 * 3600 * 1000
    try:
        with STATE.db_lock:
            cur = STATE.db.execute("DELETE FROM fleet_history WHERE ts < ?", (cutoff,))
            STATE.db.commit()
            if cur.rowcount:
                log("history_prune deleted=%s" % cur.rowcount)
    except Exception as e:
        log("history_prune_error err=%s" % type(e).__name__)


def history_query(plate: str, t_from: Optional[int], t_to: Optional[int], limit: int = 5000) -> list[dict[str, Any]]:
    assert STATE is not None
    p = norm_plate(plate)
    t_from = t_from or (now_ms() - 24 * 3600 * 1000)
    t_to = t_to or now_ms()
    limit = max(1, min(int(limit), 20000))
    with STATE.db_lock:
        rows = STATE.db.execute(
            "SELECT plate, ts, lat, lon, route, trip, heading, vehicle_id "
            "FROM fleet_history WHERE plate=? AND ts>=? AND ts<=? ORDER BY ts ASC LIMIT ?",
            (p, t_from, t_to, limit),
        ).fetchall()
    return [
        {
            "plate": r[0],
            "ts": r[1],
            "lat": r[2],
            "lon": r[3],
            "route": r[4],
            "trip": r[5],
            "heading": r[6],
            "vehicleId": r[7],
        }
        for r in rows
    ]


def vehicle_in_radius(v: dict[str, Any], lat: float, lon: float, radius: float) -> bool:
    loc = v.get("location") or {}
    try:
        return haversine_m(float(loc["lat"]), float(loc["lon"]), lat, lon) <= radius
    except Exception:
        return False


def filter_refs_for(lst: list[dict[str, Any]], refs: dict[str, Any], include: str) -> dict[str, Any]:
    inc = {x.strip() for x in (include or "").split(",") if x.strip() and x.strip() != "false"}
    if not inc or inc == {"true"}:
        inc = {"trips", "routes", "stops"}
    out: dict[str, Any] = {}
    trip_ids = {v.get("tripId") for v in lst if v.get("tripId")}
    route_ids = {v.get("routeId") for v in lst if v.get("routeId")}
    stop_ids = {v.get("stopId") for v in lst if v.get("stopId")}
    if "trips" in inc:
        src = refs.get("trips") or {}
        out["trips"] = {k: src[k] for k in trip_ids if k in src}
    if "routes" in inc:
        src = refs.get("routes") or {}
        out["routes"] = {k: src[k] for k in route_ids if k in src}
    if "stops" in inc:
        src = refs.get("stops") or {}
        out["stops"] = {k: src[k] for k in stop_ids if k in src}
    return out


def serve_from_fleet(params: dict[str, list[str]]) -> Optional[tuple[dict[str, Any], bool, float]]:
    assert STATE is not None
    snap = STATE.fleet.snapshot()
    if not snap["ok"] or not snap["fetched_at"]:
        return None
    age = snap["age"] or 0.0
    stale = age > max(POLL_ACTIVE_SEC * 2, 20) or STATE.backoff.active()
    lst: list[dict[str, Any]] = list(snap["list"])
    query = first(params, "query")
    lat_s, lon_s, rad_s = first(params, "lat"), first(params, "lon"), first(params, "radius")
    has_circle = lat_s is not None and lon_s is not None and rad_s is not None

    if not query:
        # Szűretlen körzet: a prefix-tár csak Volán, a kliens az összes
        # járművet várhatja — ne szolgáljuk ki innen.
        return None

    qn = norm_plate(query)
    if qn in PREFIXES:
        lst = [v for v in lst if norm_plate(v.get("licensePlate")).startswith(qn)]
    else:
        hit = [v for v in lst if norm_plate(v.get("licensePlate")) == qn]
        if not hit:
            return None
        lst = hit

    if has_circle:
        try:
            lat, lon, rad = float(lat_s), float(lon_s), float(rad_s)
            lst = [v for v in lst if vehicle_in_radius(v, lat, lon, rad)]
        except ValueError:
            pass

    inc = first(params, "includeReferences") or "false"
    refs = filter_refs_for(lst, snap["refs"], inc) if inc and inc != "false" else {}
    body = {
        "currentTime": snap["current_time"] or now_ms(),
        "version": 3,
        "status": "OK",
        "code": 200,
        "text": "OK",
        "data": {"limitExceeded": False, "list": lst, "references": refs},
        "ktMeta": {
            "stale": bool(stale),
            "ageSec": int(age),
            "source": "fleet-cache",
            "fetchedAt": int(snap["fetched_at"] * 1000),
            "mode": snap["mode"],
        },
    }
    return body, stale, age


def attach_meta(body: Any, stale: bool, source: str, age: Optional[float] = None) -> Any:
    if not isinstance(body, dict):
        return body
    meta = dict(body.get("ktMeta") or {})
    meta.update({"stale": bool(stale), "source": source})
    if age is not None:
        meta["ageSec"] = int(age)
    body = dict(body)
    body["ktMeta"] = meta
    return body


def scheduler() -> None:
    assert STATE is not None
    last_prune = 0.0
    # első kör azonnal, de ha backoff, vár
    while not STATE.stop.is_set():
        t0 = now()
        try:
            if now() - last_prune > 3600:
                prune_history()
                last_prune = now()
            interval = STATE.desired_poll()
            STATE.poll_interval = interval
            if STATE.backoff.active():
                rem = STATE.backoff.remaining()
                log("scheduler backoff sleep=%ss poll=%s" % (int(rem), interval))
                STATE.stop.wait(min(interval, max(1.0, rem)))
                continue
            fetch_fleet_once()
        except Exception:
            log("scheduler_error " + redact(traceback.format_exc().splitlines()[-1] if traceback.format_exc() else "err"))
        elapsed = now() - t0
        interval = STATE.desired_poll()
        STATE.poll_interval = interval
        STATE.stop.wait(max(0.2, interval - elapsed))


def stats_logger() -> None:
    assert STATE is not None
    # igazítás a perc határához
    while not STATE.stop.is_set():
        sl = 60 - (time.time() % 60)
        if STATE.stop.wait(sl):
            break
        rec = STATE.stats.snapshot_and_reset()
        snap = STATE.fleet.snapshot()
        rec["fleet_n"] = len(snap["list"]) if snap["ok"] else 0
        rec["fleet_age_sec"] = int(snap["age"] or -1) if snap["ok"] else None
        rec["poll_interval_sec"] = STATE.poll_interval
        rec["backoff"] = STATE.backoff.info()
        rec["last_client_age_sec"] = None if STATE.last_client_age() > 1e8 else int(STATE.last_client_age())
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        log(
            "stats bkk/min=%s client/min=%s hit_ratio=%s unique=%s limit=%s fleet_n=%s poll=%s"
            % (
                rec["bkk_per_min"],
                rec["client_per_min"],
                rec["cache_hit_ratio"],
                rec["unique_clients_60s"],
                rec["limit_exceeded"],
                rec["fleet_n"],
                rec["poll_interval_sec"],
            )
        )
        try:
            day = time.strftime("%Y-%m-%d")
            with open(LOG_DIR / ("stats-%s.jsonl" % day), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            log("stats_write_error err=%s" % type(e).__name__)


def extract_token(handler: BaseHTTPRequestHandler, params: dict[str, list[str]]) -> str:
    h = handler.headers
    tok = h.get("X-KT-Token") or ""
    if not tok:
        auth = h.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
    if not tok:
        tok = first(params, "token") or ""
    return tok


def client_id_of(handler: BaseHTTPRequestHandler) -> str:
    cid = handler.headers.get("X-KT-Client") or ""
    if cid:
        return cid[:80]
    ip = handler.client_address[0] if handler.client_address else "?"
    ua = (handler.headers.get("User-Agent") or "")[:80]
    return ip + "|" + ua


def authorized(tok: str) -> bool:
    assert STATE is not None
    if not tok or not STATE.token:
        return False
    if len(tok) != len(STATE.token):
        # compare_digest requires same length; still do a dummy compare
        secrets.compare_digest(STATE.token, STATE.token)
        return False
    return secrets.compare_digest(tok, STATE.token)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        try:
            msg = fmt % args
        except Exception:
            msg = fmt
        log("http %s %s" % (self.address_string(), redact(msg)))

    def _cors(self) -> None:
        origin = (self.headers.get("Origin") or "").strip()
        allowed = {"https://cs2z.github.io", "http://127.0.0.1:8787", "http://localhost:8787"}
        host = (os.environ.get("KT_HOST") or "").strip()
        extra_hosts = (os.environ.get("KT_HOST_EXTRA") or "").strip()
        for h in [host] + [x.strip() for x in extra_hosts.split(",") if x.strip()]:
            allowed.add("https://" + h)
            allowed.add("http://" + h)
        for o in (os.environ.get("KT_CORS_ORIGINS") or "").split(","):
            o = o.strip()
            if o:
                allowed.add(o)
        if origin in allowed:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "X-KT-Token, X-KT-Client, Authorization, Content-Type, Accept",
        )
        self.send_header("Access-Control-Expose-Headers", "X-KT-Cache, X-KT-Stale, X-KT-Age")
        self.send_header("Access-Control-Max-Age", "86400")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        assert STATE is not None
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            params = parse_qs_multi(parsed.query or "")
            if path == "/health":
                return self._send_health()
            tok = extract_token(self, params)
            if not authorized(tok):
                return self._send_json(401, {"status": "UNAUTHORIZED", "text": "missing or invalid token"})
            STATE.mark_client()
            cid = client_id_of(self)
            # path csoportosítás statisztikához
            sp = path
            if path.startswith("/api/"):
                sp = path.rsplit("/", 1)[-1] or path
            elif path.startswith("/sync/"):
                sp = "/sync"
            STATE.stats.add_client(sp, cid)

            if path == "/auth":
                return self._send_json(200, {"status": "OK", "now": now_ms(), "features": SERVER_FEATURES})
            if path.startswith("/sync/"):
                return self._sync_get(path[len("/sync/"):], params)

            if path == "/stats":
                return self._send_stats()
            if path == "/fleet":
                return self._send_fleet()
            if path == "/history":
                return self._send_history(params)

            futar_ep = match_futar(path)
            if futar_ep:
                return self._proxy_futar(futar_ep, params)
            rt_name = match_gtfsrt(path)
            if rt_name:
                return self._proxy_gtfsrt(rt_name)
            return self._send_json(404, {"status": "NOT_FOUND", "text": "unknown path"})
        except Exception:
            log("handler_error " + redact(traceback.format_exc().splitlines()[-1]))
            try:
                self._send_json(500, {"status": "ERROR", "text": "internal error"})
            except Exception:
                pass

    def do_PUT(self) -> None:  # noqa: N802
        self._write()

    def do_POST(self) -> None:  # noqa: N802
        self._write()

    def _write(self) -> None:
        assert STATE is not None
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            params = parse_qs_multi(parsed.query or "")
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                n = -1
            if n < 0 or n > SYNC_MAX_BYTES + 8192:
                self.close_connection = True
                return self._send_json(413, {"status": "TOO_LARGE", "text": "body too large"})
            raw = self.rfile.read(n) if n else b""
            tok = extract_token(self, params)
            if not authorized(tok):
                return self._send_json(401, {"status": "UNAUTHORIZED", "text": "missing or invalid token"})
            if not path.startswith("/sync/"):
                return self._send_json(404, {"status": "NOT_FOUND", "text": "unknown path"})
            STATE.mark_client()
            STATE.stats.add_client("/sync:put", client_id_of(self))
            sid = path[len("/sync/"):]
            if not SYNC_ID_RE.match(sid):
                return self._send_json(400, {"status": "ERROR", "text": "invalid sync id"})
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                return self._send_json(400, {"status": "ERROR", "text": "invalid json"})
            if not isinstance(body, dict):
                return self._send_json(400, {"status": "ERROR", "text": "invalid json"})
            assert SYNC is not None
            try:
                rev, data, changed = SYNC.merge(sid, body.get("data"))
            except SyncError as e:
                return self._send_json(e.code, {"status": e.status, "text": e.text, "now": now_ms()})
            self._send_json(200, {"status": "OK", "rev": rev, "now": now_ms(), "changed": changed, "data": data})
        except Exception:
            log("handler_error " + redact(traceback.format_exc().splitlines()[-1]))
            try:
                self._send_json(500, {"status": "ERROR", "text": "internal error"})
            except Exception:
                pass

    def _sync_get(self, sid: str, params: dict[str, list[str]]) -> None:
        if not SYNC_ID_RE.match(sid):
            return self._send_json(400, {"status": "ERROR", "text": "invalid sync id"})
        assert SYNC is not None
        rev, data, updated = SYNC.get(sid)
        try:
            known = int(first(params, "rev") or "-1")
        except ValueError:
            known = -1
        if rev and known == rev:
            return self._send_json(200, {"status": "OK", "rev": rev, "now": now_ms(), "unchanged": True})
        self._send_json(200, {"status": "OK", "rev": rev, "now": now_ms(), "updated": updated or None, "data": data})

    def _send(self, code: int, body: bytes, ctype: str, extra: Optional[dict[str, str]] = None) -> None:
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, code: int, obj: Any, extra: Optional[dict[str, str]] = None) -> None:
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(code, raw, "application/json; charset=utf-8", extra)

    def _cache_headers(self, status: str, stale: bool, age: Optional[float] = None) -> dict[str, str]:
        h = {"X-KT-Cache": status, "X-KT-Stale": "1" if stale else "0"}
        if age is not None:
            h["X-KT-Age"] = str(int(age))
        return h

    def _send_health(self) -> None:
        assert STATE is not None
        snap = STATE.fleet.snapshot()
        bo = STATE.backoff.info()
        self._send_json(
            200,
            {
                "ok": True,
                "uptime_sec": int(now() - STATE.started_at),
                "fleet_ok": snap["ok"],
                "fleet_n": len(snap["list"]) if snap["ok"] else 0,
                "fleet_age_sec": int(snap["age"] or -1) if snap["fetched_at"] else None,
                "fleet_mode": snap["mode"] or None,
                "poll_interval_sec": STATE.poll_interval,
                "backoff": bo,
                "key_configured": bool(STATE.api_key),
                "features": SERVER_FEATURES,
            },
        )

    def _send_stats(self) -> None:
        assert STATE is not None
        # aktuális perc (még nem lezárt) + előzmény
        with STATE.stats.lock:
            cur_bkk = dict(STATE.stats.bkk)
            cur_client = dict(STATE.stats.client)
            hit = STATE.stats.cache_hit
            stale = STATE.stats.cache_stale
            miss = STATE.stats.cache_miss
            infl = STATE.stats.inflight_join
            lim = STATE.stats.limit_exceeded
            unique = sum(1 for t in STATE.stats.clients.values() if now() - t < 60)
        looked = hit + stale + miss
        snap = STATE.fleet.snapshot()
        self._send_json(
            200,
            {
                "current_partial_minute": {
                    "bkk": sum(cur_bkk.values()),
                    "bkk_by_endpoint": cur_bkk,
                    "client": sum(cur_client.values()),
                    "client_by_path": cur_client,
                    "cache_hit": hit,
                    "cache_stale": stale,
                    "cache_miss": miss,
                    "inflight_join": infl,
                    "cache_hit_ratio": (round((hit + stale) / looked, 3) if looked else None),
                    "unique_clients_60s": unique,
                    "limit_exceeded": lim,
                    "second_in_minute": int(time.time() % 60),
                },
                "recent_minutes": STATE.stats.recent(60),
                "fleet": {
                    "ok": snap["ok"],
                    "n": len(snap["list"]) if snap["ok"] else 0,
                    "age_sec": int(snap["age"] or -1) if snap["fetched_at"] else None,
                    "mode": snap["mode"],
                    "notes": snap["notes"],
                },
                "poll_interval_sec": STATE.poll_interval,
                "backoff": STATE.backoff.info(),
                "uptime_sec": int(now() - STATE.started_at),
            },
        )

    def _send_fleet(self) -> None:
        assert STATE is not None
        snap = STATE.fleet.snapshot()
        if not snap["ok"] or not snap["fetched_at"]:
            return self._send_json(
                503,
                {"status": "NO_DATA", "text": "fleet cache empty", "ktMeta": {"stale": True, "source": "none"}},
                self._cache_headers("miss", True),
            )
        age = snap["age"] or 0.0
        stale = age > max(POLL_ACTIVE_SEC * 2, 20) or STATE.backoff.active()
        body = {
            "currentTime": snap["current_time"] or now_ms(),
            "version": 3,
            "status": "OK",
            "code": 200,
            "text": "OK",
            "data": {
                "limitExceeded": False,
                "list": snap["list"],
                "references": snap["refs"],
            },
            "ktMeta": {
                "stale": stale,
                "ageSec": int(age),
                "source": "fleet-cache",
                "fetchedAt": int(snap["fetched_at"] * 1000),
                "mode": snap["mode"],
                "notes": snap["notes"],
            },
        }
        STATE.stats.add_cache("stale" if stale else "hit")
        self._send_json(200, body, self._cache_headers("stale" if stale else "hit", stale, age))

    def _send_history(self, params: dict[str, list[str]]) -> None:
        plate = first(params, "plate") or ""
        if not plate:
            return self._send_json(400, {"status": "ERROR", "text": "plate required"})
        def maybe_int(name: str) -> Optional[int]:
            s = first(params, name)
            if not s:
                return None
            try:
                return int(s)
            except ValueError:
                return None
        rows = history_query(plate, maybe_int("from"), maybe_int("to"), maybe_int("limit") or 5000)
        self._send_json(200, {"status": "OK", "plate": norm_plate(plate), "n": len(rows), "points": rows})

    def _proxy_futar(self, endpoint: str, params: dict[str, list[str]]) -> None:
        if endpoint == "vehicles-for-location.json":
            served = serve_from_fleet(params)
            if served is not None:
                body, stale, age = served
                STATE.stats.add_cache("stale" if stale else "hit")
                return self._send_json(
                    200, body, self._cache_headers("fleet" if not stale else "fleet-stale", stale, age)
                )
        http, body, st, stale = fetch_futar_cached(endpoint, params)
        if stale and isinstance(body, dict):
            body = attach_meta(body, True, "cache-stale" if st != "miss" else "upstream-or-stale")
        elif isinstance(body, dict):
            body = attach_meta(body, False, "cache" if st == "hit" else "upstream")
        # ha van cache entry, adjuk az életkort
        ck = cache_key("futar", endpoint, params)
        ent = cache_get(ck)
        age = ent.age() if ent else None
        self._send_json(http if http else 502, body, self._cache_headers(st, stale, age))

    def _proxy_gtfsrt(self, name: str) -> None:
        assert STATE is not None
        filename = name if name.endswith(".pb") else name + ".pb"
        ck = cache_key("gtfs-rt", filename, {})
        ttl = TTL_BY_ENDPOINT["gtfs-rt"]
        ent = cache_get(ck)
        if ent and ent.fresh():
            STATE.stats.add_cache("hit")
            return self._send(
                ent.status, ent.payload, ent.content_type, self._cache_headers("hit", False, ent.age())
            )
        if STATE.backoff.active() and ent:
            STATE.stats.add_cache("stale")
            return self._send(
                ent.status, ent.payload, ent.content_type, self._cache_headers("stale", True, ent.age())
            )
        ev = inflight_join_or_begin(ck)
        if ev is not None:
            STATE.stats.add_cache("inflight")
            boxed = inflight_wait(ev, ck)
            if boxed is not None:
                http, raw, ctype = boxed
                return self._send(http, raw, ctype, self._cache_headers("inflight", False))
            if ent:
                return self._send(ent.status, ent.payload, ent.content_type, self._cache_headers("stale", True, ent.age()))
            return self._send_json(503, {"status": "ERROR", "text": "in-flight timeout"})
        try:
            respect_min_gap(ck)
            if STATE.backoff.active():
                if ent:
                    STATE.stats.add_cache("stale")
                    inflight_finish(ck, (ent.status, ent.payload, ent.content_type))
                    return self._send(ent.status, ent.payload, ent.content_type, self._cache_headers("stale", True, ent.age()))
                inflight_finish(ck, None)
                return self._send_json(503, {"status": "BACKOFF", "text": "BKK LIMIT_EXCEEDED backoff"})
            STATE.stats.add_cache("miss")
            http, raw, ctype = bkk_get_bytes(GTFSRT_BASE, filename)
            if http == 200:
                cache_put(ck, CacheEntry("bytes", raw, ctype, now(), ttl, http))
            elif ent:
                inflight_finish(ck, (ent.status, ent.payload, ent.content_type))
                return self._send(ent.status, ent.payload, ent.content_type, self._cache_headers("stale", True, ent.age()))
            inflight_finish(ck, (http, raw, ctype))
            self._send(http, raw, ctype, self._cache_headers("miss", http != 200))
        except Exception as e:
            log("gtfsrt_error name=%s err=%s" % (filename, type(e).__name__))
            inflight_finish(ck, None)
            if ent:
                STATE.stats.add_cache("stale")
                return self._send(ent.status, ent.payload, ent.content_type, self._cache_headers("stale", True, ent.age()))
            self._send_json(502, {"status": "ERROR", "text": "upstream error"})


def match_futar(path: str) -> Optional[str]:
    prefixes = (
        "/api/query/v1/ws/otp/api/where/",
        "/api/where/",
    )
    for p in prefixes:
        if path.startswith(p):
            ep = path[len(p):]
            if SAFE_EP_RE.match(ep) and ep.endswith(".json"):
                return ep
    return None


def match_gtfsrt(path: str) -> Optional[str]:
    prefixes = (
        "/api/query/v1/ws/gtfs-rt/full/",
        "/api/gtfs-rt/",
    )
    for p in prefixes:
        if path.startswith(p):
            name = path[len(p):]
            if SAFE_RT_RE.match(name):
                return name
    return None


def main() -> int:
    global STATE, SYNC
    ensure_dirs()
    if is_mock() and not (os.environ.get("BKK_API_KEY") or "").strip():
        os.environ["BKK_API_KEY"] = "KTMOCK"
    if not os.environ.get("BKK_API_KEY"):
        # ne írjuk ki, csak jelezzük a hiányt
        sys.stderr.write("error: BKK_API_KEY is not set\n")
        return 2
    STATE = State()
    if not STATE.api_key:
        return 2
    SYNC = SyncStore(SYNC_DB_PATH)
    log("start bind=%s:%s poll_active=%s poll_idle=%s mock=%s" % (BIND, PORT, POLL_ACTIVE_SEC, POLL_IDLE_SEC, is_mock()))
    # pid
    try:
        (VAR_DIR / "server.pid").write_text(str(os.getpid()) + "\n")
    except Exception:
        pass
    th = threading.Thread(target=scheduler, name="kt-scheduler", daemon=True)
    th.start()
    sl = threading.Thread(target=stats_logger, name="kt-stats", daemon=True)
    sl.start()
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    log("listening http://%s:%s" % (BIND, PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("shutdown keyboard")
    finally:
        STATE.stop.set()
        httpd.server_close()
        try:
            STATE.db.close()
        except Exception:
            pass
        try:
            if SYNC is not None:
                SYNC.conn.close()
        except Exception:
            pass
        log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
