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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depot as ktdepot  # KKMD-4: tárolók (server/depot.py)
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
SERVER_FEATURES = ["futar", "gtfs-rt", "fleet", "history", "auth", "sync", "lastknown", "offline", "volan-gtfs", "mavinform", "depot", "volan-extra"]

# v1.22: utolsó ismert hely rendszámonként (plate_last – soha nem törlődik; a teljes nyomvonal fleet_history marad HISTORY_DAYS napig)
LASTKNOWN_R_DEFAULT = 1500
LASTKNOWN_R_MAX = 5000
OFFLINE_DEPOT_R = 800
OFFLINE_MINAGE_DEFAULT = 3600
DEPOTS = [
    ("Hunyadi", 47.4306299, 19.0423898),
    ("Mogyoródi", 47.5069959, 19.112158),
    ("Etele", 47.464017, 19.0224192),
    ("Pevdi", 47.5969396, 18.9527357),
    ("Szigethalom", 47.3317937, 19.0025362),
    ("javító FÓT", 47.5892031, 19.1497629),  # v1.64: MÁV Személyszállítási Zrt. Fót Autóbuszos Műszaki Telephely (app: „javító FÓT telephely”)
]

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
    agencies: dict[str, Any] = {}
    if q:
        qn = norm_plate(q)
        vehicles = [v for v in vehicles if norm_plate(v.get("licensePlate")).startswith(qn) or norm_plate(v.get("licensePlate")) == qn]
    else:
        # Szűretlen 20 km (éjszakai Volán-gyűjtés tesztje): prefix buszok + idegen rendszámú Volán + nem-Volán.
        # Az előtagos hívások query-vel jönnek, ezt az ágat nem érintik.
        vehicles[0]["vehicleId"] = "volan_mock:%s" % vehicles[0]["licensePlate"]
        extras = [
            {
                "vehicleId": "volan_pig001",
                "licensePlate": "PIG001",
                "label": "PIG001",
                "location": {"lat": CENTER_LAT + 0.02, "lon": CENTER_LON + 0.02},
                "bearing": 10,
                "lastUpdateTime": now_i,
                "status": "STOPPED_AT",
            },
            {
                "vehicleId": "bkk:rdb001",
                "licensePlate": "RDB001",
                "label": "RDB001",
                "location": {"lat": CENTER_LAT + 0.021, "lon": CENTER_LON + 0.021},
                "bearing": 20,
                "tripId": "volan_MOCKTRIP_RDB",
                "routeId": "volan_1000",
                "lastUpdateTime": now_i,
                "status": "IN_TRANSIT_TO",
            },
            {
                "vehicleId": "bkk:nkv001",
                "licensePlate": "NKV001",
                "label": "NKV001",
                "location": {"lat": CENTER_LAT + 0.022, "lon": CENTER_LON + 0.022},
                "bearing": 30,
                "tripId": "BKK_MOCKTRIP_NKV",
                "routeId": "BKK_VOLANTEST",
                "lastUpdateTime": now_i,
                "status": "IN_TRANSIT_TO",
            },
            {
                "vehicleId": "bkk:bkv001",
                "licensePlate": "BKV001",
                "label": "BKV001",
                "location": {"lat": CENTER_LAT + 0.03, "lon": CENTER_LON + 0.03},
                "bearing": 40,
                "tripId": "BKK_MOCKTRIP_BKV",
                "routeId": "BKK_0090",
                "lastUpdateTime": now_i,
                "status": "IN_TRANSIT_TO",
            },
            {
                "vehicleId": "bkk:hev001",
                "licensePlate": "HEV001",
                "label": "HEV001",
                "location": {"lat": CENTER_LAT + 0.031, "lon": CENTER_LON + 0.031},
                "bearing": 50,
                "tripId": "BKK_MOCKTRIP_HEV",
                "routeId": "BKK_H8",
                "lastUpdateTime": now_i,
                "status": "IN_TRANSIT_TO",
            },
        ]
        vehicles.extend(extras)
        trips["volan_MOCKTRIP_RDB"] = {"id": "volan_MOCKTRIP_RDB", "routeId": "volan_1000", "tripHeadsign": "Mock Volán RDB"}
        trips["BKK_MOCKTRIP_NKV"] = {"id": "BKK_MOCKTRIP_NKV", "routeId": "BKK_VOLANTEST", "tripHeadsign": "Mock Volán NKV"}
        trips["BKK_MOCKTRIP_BKV"] = {"id": "BKK_MOCKTRIP_BKV", "routeId": "BKK_0090", "tripHeadsign": "Mock BKV"}
        trips["BKK_MOCKTRIP_HEV"] = {"id": "BKK_MOCKTRIP_HEV", "routeId": "BKK_H8", "tripHeadsign": "Mock HÉV"}
        routes["volan_1000"] = {"id": "volan_1000", "shortName": "1000", "type": "BUS", "agencyId": "volan_volan"}
        routes["BKK_VOLANTEST"] = {"id": "BKK_VOLANTEST", "shortName": "VT", "type": "BUS", "agencyId": "volan_volan"}
        routes["BKK_0090"] = {"id": "BKK_0090", "shortName": "9", "type": "BUS", "agencyId": "BKK_BKV"}
        routes["BKK_H8"] = {"id": "BKK_H8", "shortName": "H8", "type": "RAIL", "agencyId": "BKK_HEV"}
        agencies["volan_volan"] = {"id": "volan_volan", "name": "Volánbusz"}
        agencies["BKK_BKV"] = {"id": "BKK_BKV", "name": "BKV Zrt."}
        agencies["BKK_HEV"] = {"id": "BKK_HEV", "name": "MÁV Személyszállítási"}
    refs_body: dict[str, Any] = {"trips": trips, "routes": routes, "stops": stops}
    if agencies:
        refs_body["agencies"] = agencies
    body: dict[str, Any] = {
        "currentTime": now_i,
        "version": 3,
        "status": "OK",
        "code": 200,
        "text": "OK",
        "data": {"limitExceeded": False, "list": vehicles, "references": refs_body},
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
        # KKMD-18: idegen rendszámú Volán buszok (az éjszakai 20 km-es hívásból), rendszám → (jármű, gyűjtés ideje ms)
        self.extra: dict[str, tuple[dict[str, Any], int]] = {}
        self.extra_refs: dict[str, Any] = {"trips": {}, "routes": {}}

    def set_extra(self, lst: list[dict[str, Any]], refs: dict[str, Any], t_ms: int) -> None:
        """Az éjszakai hívás teljes Volán-extra készlete felváltja az előzőt (ami nincs benne, az már nincs a 20 km-en belül)."""
        ex: dict[str, tuple[dict[str, Any], int]] = {}
        for v in lst:
            p = norm_plate(v.get("licensePlate"))
            if p:
                w = dict(v)
                w["ktVolanExtra"] = True
                ex[p] = (w, int(t_ms))
        tr = {k: x for k, x in ((refs or {}).get("trips") or {}).items() if any(e[0].get("tripId") == k for e in ex.values())}
        ro = {k: x for k, x in ((refs or {}).get("routes") or {}).items() if any(e[0].get("routeId") == k for e in ex.values())}
        with self.lock:
            self.extra = ex
            self.extra_refs = {"trips": tr, "routes": ro}

    def _extra_live(self, base_plates: set[str]) -> list[dict[str, Any]]:
        t = now_ms()
        return [
            v for p, (v, ts) in sorted(self.extra.items())
            if p not in base_plates and t - ts <= VOLAN_EXTRA_TTL_SEC * 1000
        ]

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

    def snapshot(self, include_extra: bool = True, only_extra: bool = False) -> dict[str, Any]:
        with self.lock:
            lst, refs = self.list, self.refs
            if include_extra or only_extra:
                base = {norm_plate(v.get("licensePlate")) for v in self.list}
                ex = self._extra_live(base)
                if only_extra:
                    lst = ex
                    refs = {"trips": dict(self.extra_refs.get("trips") or {}), "routes": dict(self.extra_refs.get("routes") or {})}
                elif ex:
                    lst = list(self.list) + ex
                    refs = dict(self.refs)
                    for k in ("trips", "routes"):
                        d = dict(refs.get(k) or {})
                        d.update(self.extra_refs.get(k) or {})
                        refs[k] = d
            return {
                "list": lst,
                "refs": refs,
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plate_last (
              plate TEXT PRIMARY KEY,
              ts INTEGER NOT NULL,
              lat REAL,
              lon REAL,
              route TEXT,
              trip TEXT,
              vehicle_id TEXT,
              first_seen INTEGER
            )
            """
        )
        # v1.37: plate_last.sig – 1: a ts a busz saját utolsó jele (FUTÁR lastUpdateTime), 0: régi sor (a ts a gyűjtés ideje volt)
        if "sig" not in [r[1] for r in conn.execute("PRAGMA table_info(plate_last)").fetchall()]:
            conn.execute("ALTER TABLE plate_last ADD COLUMN sig INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_plate_last_lat_lon ON plate_last(lat, lon)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_plate_last_ts ON plate_last(ts)")
        # KKMD-18: az éjszakai 20 km-es hívásban látott idegen rendszámú Volán buszok (a kliens ezeket az előtag-szabálytól függetlenül mutatja)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS volan_extra (plate TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)"
        )
        ktdepot.init_db(conn)  # KKMD-4: night_pos, depot_candidate, depot, plate_depot, depot_meta
        # indulási feltöltés a meglévő fleet_history-ból (rendszámonként a legutolsó sor; az első látás = legkorábbi sor)
        conn.execute(
            """
            INSERT INTO plate_last(plate, ts, lat, lon, route, trip, vehicle_id, first_seen)
            SELECT h.plate, h.ts, h.lat, h.lon, h.route, h.trip, h.vehicle_id, m.mn
            FROM fleet_history h
            JOIN (SELECT plate, MAX(ts) AS mx, MIN(ts) AS mn FROM fleet_history GROUP BY plate) m
              ON h.plate = m.plate AND h.ts = m.mx
            WHERE 1
            ON CONFLICT(plate) DO UPDATE SET
              ts = excluded.ts, lat = excluded.lat, lon = excluded.lon, route = excluded.route,
              trip = excluded.trip, vehicle_id = excluded.vehicle_id,
              first_seen = MIN(COALESCE(plate_last.first_seen, excluded.first_seen), excluded.first_seen)
            WHERE excluded.ts > plate_last.ts
            """
        )
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


VOLAN_ID_PREFIX = "volan_"
VOLAN_AGENCY_ID = "volan_volan"
NIGHT_VOLAN_EVERY_SEC = 10 * 60  # éjszakai szűretlen 20 km-es hívás, legfeljebb ennyinként
NIGHT_VOLAN_INCLUDE = "trips,routes,agencies"
# KKMD-18: az extra buszok ennyi ideig maradnak az élő flotta-tárban a legutóbbi éjszakai hívás után (2 hívásnyi idő)
VOLAN_EXTRA_TTL_SEC = 2 * NIGHT_VOLAN_EVERY_SEC
_last_night_volan = 0.0


def is_volan_vehicle(v: dict[str, Any], refs: Optional[dict[str, Any]] = None) -> bool:
    """BKK-irányítású Volán: vehicleId/routeId 'volan_' előtag, vagy a járat ügynöksége volan_volan.

    A 'MÁV Személyszállítási' ügynökségnevet nem használjuk (HÉV/vonat is az).
    Éjszaka leállított busznak gyakran nincs routeId-ja: akkor a vehicleId dönt.
    """
    vid = str(v.get("vehicleId") or "")
    if vid.lower().startswith(VOLAN_ID_PREFIX):
        return True
    rid = str(v.get("routeId") or "")
    if rid.lower().startswith(VOLAN_ID_PREFIX):
        return True
    aids: list[str] = []
    if v.get("agencyId"):
        aids.append(str(v.get("agencyId") or ""))
    routes = (refs or {}).get("routes") or {}
    r = routes.get(rid) if rid else None
    if isinstance(r, dict) and r.get("agencyId"):
        aids.append(str(r.get("agencyId") or ""))
    return any(a.lower() == VOLAN_AGENCY_ID for a in aids)


def night_volan_params() -> dict[str, list[str]]:
    return {
        "lat": [str(CENTER_LAT)],
        "lon": [str(CENTER_LON)],
        "radius": [str(FLEET_RADIUS_CITY)],
        "includeReferences": [NIGHT_VOLAN_INCLUDE],
    }


def prefix_fleet_plates() -> set[str]:
    assert STATE is not None
    snap = STATE.fleet.snapshot(include_extra=False)
    out: set[str] = set()
    for v in snap["list"] or []:
        p = norm_plate(v.get("licensePlate"))
        if p:
            out.add(p)
    return out


def maybe_fetch_night_volan(now_ms_val: Optional[int] = None, force: bool = False) -> bool:
    """23:00–03:00 (Europe/Budapest): egy szűretlen 20 km-es vehicles-for-location, max. 10 percenként.

    Csak a Volán járműveket tartja meg, az előtagos flotta rendszámaival deduplikálja,
    és a night_pos-ba írja (record_live). KKMD-18: ezek az idegen rendszámú Volán buszok
    az élő flotta-tárba (ktVolanExtra jelöléssel, VOLAN_EXTRA_TTL_SEC-ig), a fleet_history-ba
    és a plate_last-ba is bekerülnek, mint az előtagos buszok. Nem-Volán jármű sehova nem kerül.
    """
    global _last_night_volan
    assert STATE is not None
    t_ms = now_ms() if now_ms_val is None else now_ms_val
    if not ktdepot.night_of(t_ms):
        return False
    if not force and _last_night_volan and (t_ms / 1000.0 - _last_night_volan) < NIGHT_VOLAN_EVERY_SEC:
        return False
    if STATE.backoff.active():
        log("night_volan_skip backoff remaining=%ss" % int(STATE.backoff.remaining()))
        return False
    params = night_volan_params()
    ck = cache_key("futar", "vehicles-for-location.json", params)
    respect_min_gap(ck)
    try:
        http, body = bkk_get_json("vehicles-for-location.json", params)
    except Exception as e:
        log("night_volan_error err=%s" % type(e).__name__)
        return False
    # A hívás megtörtént: a 10 perces ritkítás ettől számít, sikertelen választ se ismételjük azonnal.
    _last_night_volan = t_ms / 1000.0
    if not isinstance(body, dict):
        log("night_volan_error err=invalid_body")
        return False
    if is_limit_exceeded(http, body):
        log("night_volan_error err=%s" % (body.get("status") or http))
        return False
    if http != 200 or body.get("status") not in (None, "OK"):
        log("night_volan_error err=http=%s status=%s" % (http, body.get("status")))
        return False
    cache_put(ck, CacheEntry("json", body, "application/json", now(), TTL_BY_ENDPOINT["vehicles-for-location.json"], http))
    data = body.get("data") or {}
    if data.get("limitExceeded"):
        log("night_volan note=data.limitExceeded (truncated)")
    refs = data.get("references") or {}
    lst = data.get("list") or []
    volan = [v for v in lst if is_volan_vehicle(v, refs)]
    uniq = uniq_vehicles(volan)
    have = prefix_fleet_plates()
    extra: list[dict[str, Any]] = []
    for v in uniq:
        p = norm_plate(v.get("licensePlate"))
        if not p or p in have:
            continue
        extra.append(v)
    try:
        n = ktdepot.record_live(STATE.db, STATE.db_lock, extra, t_ms, norm_plate, signal_ms)
    except Exception as e:
        log("night_volan_record_error err=%s" % type(e).__name__)
        return False
    try:
        volan_extra_store(extra, refs, t_ms)
    except Exception as e:
        log("night_volan_extra_error err=%s" % type(e).__name__)
    log("night_volan ok n=%s extra=%s recorded=%s" % (len(volan), len(extra), n))
    return True


_VOLAN_EXTRA_SET: Optional[set[str]] = None


def volan_extra_plates() -> set[str]:
    """KKMD-18: az eddig látott idegen rendszámú Volán buszok (volan_extra tábla), memóriában tartva."""
    global _VOLAN_EXTRA_SET
    assert STATE is not None
    if _VOLAN_EXTRA_SET is None:
        with STATE.db_lock:
            _VOLAN_EXTRA_SET = {r[0] for r in STATE.db.execute("SELECT plate FROM volan_extra")}
    return _VOLAN_EXTRA_SET


def volan_extra_store(extra: list[dict[str, Any]], refs: dict[str, Any], t_ms: int) -> None:
    """KKMD-18: az éjszakai hívás idegen rendszámú Volán buszai → élő flotta-tár, fleet_history, plate_last, volan_extra.
    A night_pos-t a hívó már írta (record_live), ezért a store_history itt nem írja újra."""
    assert STATE is not None
    STATE.fleet.set_extra(extra, refs, t_ms)
    if not extra:
        return
    store_history(extra, refs, depot=False, poll_ms=t_ms)
    ps = sorted({norm_plate(v.get("licensePlate")) for v in extra if norm_plate(v.get("licensePlate"))})
    with STATE.db_lock:
        STATE.db.executemany(
            "INSERT INTO volan_extra(plate, first_seen, last_seen) VALUES (?,?,?) "
            "ON CONFLICT(plate) DO UPDATE SET last_seen=MAX(volan_extra.last_seen, excluded.last_seen)",
            [(p, int(t_ms), int(t_ms)) for p in ps],
        )
        STATE.db.commit()
    volan_extra_plates().update(ps)


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


def store_history(lst: list[dict[str, Any]], refs: dict[str, Any], depot: bool = True, poll_ms: Optional[int] = None) -> None:
    assert STATE is not None
    if depot:
        try:  # KKMD-4: éjszakai helyek (23:00–03:00) a már lekért flottából – nincs külön BKK-hívás
            ktdepot.record_live(STATE.db, STATE.db_lock, lst, now_ms(), norm_plate, signal_ms)
        except Exception as e:
            log("depot_record_error err=%s" % type(e).__name__)
    ts = now_ms() if poll_ms is None else int(poll_ms)
    rows = []
    sigs: dict[str, tuple[int, int]] = {}  # v1.37: rendszám → (a busz saját jelének ideje ms, sig)
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
        sigs[plate] = signal_ms(v, ts)
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
            # v1.37: plate_last.ts = a busz SAJÁT utolsó jele (FUTÁR lastUpdateTime; ha nincs: a gyűjtés ideje), nem a gyűjtés ideje.
            # Így a FUTÁR-ban még szereplő, de régóta jel nélküli busz is „régóta nem látott” lesz; friss jelnél (menet vagy ASP) azonnal frissül.
            # A régi (sig=0, gyűjtési idős) sor az első gyűjtéskor felülíródik akkor is, ha a valódi jel régebbi.
            STATE.db.executemany(
                "INSERT INTO plate_last(plate,ts,lat,lon,route,trip,vehicle_id,first_seen,sig) VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(plate) DO UPDATE SET ts=excluded.ts, lat=excluded.lat, lon=excluded.lon, route=excluded.route, "
                "trip=excluded.trip, vehicle_id=excluded.vehicle_id, sig=excluded.sig "
                "WHERE excluded.ts >= plate_last.ts OR plate_last.sig = 0",
                [(r[0], sigs[r[0]][0], r[2], r[3], r[4], r[5], r[7], sigs[r[0]][0], sigs[r[0]][1]) for r in rows],
            )
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


def signal_ms(v: dict[str, Any], poll_ms: int) -> tuple[int, int]:
    """v1.37: a busz saját utolsó jelének ideje (ms) a FUTÁR lastUpdateTime-ból (mp vagy ms), legfeljebb a gyűjtés ideje.
    Ha hiányzik / hibás: a gyűjtés ideje. Visszatér: (ts_ms, sig) – sig=1, ha a busz saját jeléből jön."""
    try:
        lu = float(v.get("lastUpdateTime") or 0)
    except (TypeError, ValueError):
        lu = 0
    if lu <= 0:
        return poll_ms, 0
    ms = int(lu if lu > 1e11 else lu * 1000)
    return min(ms, poll_ms), 1


def live_fresh_plates(max_age_s: int = OFFLINE_MINAGE_DEFAULT) -> set[str]:
    """v1.37: a FUTÁR-ban most szereplő rendszámok, amelyek saját jele max_age_s-nél frissebb (menetben vagy ASP)."""
    assert STATE is not None
    snap = STATE.fleet.snapshot()
    t = now_ms()
    out: set[str] = set()
    for v in snap["list"] or []:
        p = norm_plate(v.get("licensePlate"))
        if not p:
            continue
        ts, _sig = signal_ms(v, t)
        if t - ts < max_age_s * 1000:
            out.add(p)
    return out


def nearest_depot(lat: Optional[float], lon: Optional[float], rmax: float = OFFLINE_DEPOT_R) -> tuple[Optional[str], Optional[int]]:
    if lat is None or lon is None:
        return None, None
    best, bd = None, None
    for n, dlat, dlon in DEPOTS:
        d = haversine_m(lat, lon, dlat, dlon)
        if d <= rmax and (bd is None or d < bd):
            best, bd = n, d
    return best, (int(round(bd)) if bd is not None else None)


def live_plates() -> set[str]:
    assert STATE is not None
    snap = STATE.fleet.snapshot()
    out: set[str] = set()
    for v in snap["list"] or []:
        p = norm_plate(v.get("licensePlate"))
        if p:
            out.add(p)
    return out


def _pl_row(r: Any, t_now: int, lat0: Optional[float] = None, lon0: Optional[float] = None) -> dict[str, Any]:
    dep, dd = nearest_depot(r[2], r[3])
    o = {
        "plate": r[0],
        "ts": r[1],
        "lat": r[2],
        "lon": r[3],
        "route": r[4] or "",
        "trip": r[5] or "",
        "vehicleId": r[6] or "",
        "firstSeen": r[7],
        "ageSec": max(0, int((t_now - r[1]) / 1000)),
        "depot": dep,
        "depotDist": dd,
    }
    if r[0] in volan_extra_plates():
        o["volanExtra"] = True  # KKMD-18: idegen rendszámú Volán busz (nem előtagos)
    if lat0 is not None and lon0 is not None and r[2] is not None and r[3] is not None:
        o["dist"] = int(round(haversine_m(lat0, lon0, r[2], r[3])))
    return o


def lastknown_query(lat: float, lon: float, r: float, maxage: Optional[int] = None, limit: int = 300) -> list[dict[str, Any]]:
    """Rendszámonként a legutolsó hely (plate_last) a körön belül; az élő flottában lévő rendszámok nélkül.
    Bounding-box előszűrés indexen (lat, lon), utána pontos távolság."""
    assert STATE is not None
    r = max(10.0, min(float(r), float(LASTKNOWN_R_MAX)))
    dlat = r / 111320.0
    dlon = r / (111320.0 * max(0.2, math.cos(math.radians(lat))))
    t_now = now_ms()
    args: list[Any] = [lat - dlat, lat + dlat, lon - dlon, lon + dlon]
    cond = ""
    if maxage:
        cond = " AND ts >= ?"
        args.append(t_now - int(maxage) * 1000)
    with STATE.db_lock:
        rows = STATE.db.execute(
            "SELECT plate, ts, lat, lon, route, trip, vehicle_id, first_seen FROM plate_last "
            "WHERE lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?" + cond,
            args,
        ).fetchall()
    live = live_plates()
    out = [_pl_row(x, t_now, lat, lon) for x in rows if x[0] not in live]
    out = [o for o in out if o.get("dist", 1e9) <= r]
    out.sort(key=lambda o: o["dist"])
    return out[: max(1, min(int(limit), 2000))]


def lastknown_plate(plate: str) -> Optional[dict[str, Any]]:
    assert STATE is not None
    p = norm_plate(plate)
    with STATE.db_lock:
        r = STATE.db.execute(
            "SELECT plate, ts, lat, lon, route, trip, vehicle_id, first_seen FROM plate_last WHERE plate=?", (p,)
        ).fetchone()
    if not r:
        return None
    o = _pl_row(r, now_ms())
    o["live"] = p in live_plates()
    return o


def offline_query(minage: int = OFFLINE_MINAGE_DEFAULT) -> list[dict[str, Any]]:
    assert STATE is not None
    t_now = now_ms()
    with STATE.db_lock:
        rows = STATE.db.execute(
            "SELECT plate, ts, lat, lon, route, trip, vehicle_id, first_seen FROM plate_last WHERE ts <= ? ORDER BY ts ASC",
            (t_now - max(0, int(minage)) * 1000,),
        ).fetchall()
    # v1.37: csak a FUTÁR-ban friss (minage-nél újabb) saját jellel szereplő busz marad ki; a listában lévő, de régóta jel nélküli nem
    live = live_fresh_plates(max(1, int(minage)))
    return [_pl_row(x, t_now) for x in rows if x[0] not in live]


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
            try:  # KKMD-4: éjszakai OFF-pillanatkép + 03:15-ös klaszterezés (naponta egyszer)
                ktdepot.tick(STATE.db, STATE.db_lock, now_ms(), log)
            except Exception as e:
                log("depot_tick_error err=%s" % type(e).__name__)
            if now() - last_prune > 3600:
                prune_history()
                try:
                    ktdepot.prune(STATE.db, STATE.db_lock, now_ms())
                except Exception:
                    pass
                last_prune = now()
            interval = STATE.desired_poll()
            STATE.poll_interval = interval
            if STATE.backoff.active():
                rem = STATE.backoff.remaining()
                log("scheduler backoff sleep=%ss poll=%s" % (int(rem), interval))
                STATE.stop.wait(min(interval, max(1.0, rem)))
                continue
            fetch_fleet_once()
            maybe_fetch_night_volan()
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


# ---------------------------------------------------------------------------
# srv-volan1: országos Volánbusz statikus GTFS (KTI, nyilvános) + MÁVINFORM RSS
# Kulcs nélküli, nyilvános források; a BKK-kulcshoz nem nyúl. Csak stdlib.
# ---------------------------------------------------------------------------
VOLAN_DIR = DATA_DIR / "volan"
VOLAN_GTFS_URL = (os.environ.get("KT_VOLAN_GTFS_URL") or "https://gtfs.kti.hu/public-gtfs/volanbusz_gtfs.zip").strip()
MAVINFORM_URL = (os.environ.get("KT_MAVINFORM_URL") or "https://www.mavcsoport.hu/mavinform/rss.xml").strip()
VOLAN_GTFS_ZIP = VOLAN_DIR / "volanbusz_gtfs.zip"
VOLAN_GTFS_META = VOLAN_DIR / "gtfs_meta.json"
VOLAN_GTFS_DB = VOLAN_DIR / "gtfs_index.sqlite"
VOLAN_ROUTES_GZ = VOLAN_DIR / "routes.json.gz"
VOLAN_STOPS_GZ = VOLAN_DIR / "stops.json.gz"
MAVINFORM_STORE = VOLAN_DIR / "mavinform.json"
VOLAN_GTFS_AT = os.environ.get("KT_VOLAN_GTFS_AT", "03:30")         # Budapest idő, napi letöltés
VOLAN_GTFS_MAX_AGE = 24 * 3600                                       # induláskor: ha nincs / ennél régebbi
VOLAN_GTFS_MAX_BYTES = int(os.environ.get("KT_VOLAN_GTFS_MAX_BYTES", str(400 * 1024 * 1024)))
VOLAN_MIN_FREE_BYTES = int(os.environ.get("KT_VOLAN_MIN_FREE", str(350 * 1024 * 1024)))
MAVINFORM_EVERY = int(os.environ.get("KT_MAVINFORM_EVERY", "300"))
MAVINFORM_MAX_ITEMS = 500
MAVINFORM_MAX_DAYS = 30
MAVINFORM_MAX_BYTES = 2 * 1024 * 1024
VOLAN_UA = "kt-server/0.2 (KT app, VOLAN Agglo tartalek-szolgalat; +https://cs2z.github.io/kt-app/)"
MAVINFORM_CATS: list[tuple[str, str]] = [   # ékezet- és kisbetű-független regexek (fold() után)
    ("potlas", r"potlobusz|vonatpotl|\bpotlo\b|\bpotlas|\bpotol(?:ja|jak|juk)\b"),
    ("vaganyzar", r"vaganyzar"),
    ("kimarad", r"kimarad|elmarad|nem kozlekedik|nem kozlekednek|\btorol|\btorli"),
    ("volan", r"volan"),
    ("autobusz", r"busz"),
    ("keses", r"\bkeses|\bkesik\b|\bkesnek\b|\bkesve\b|\bkeso\b"),
    ("korlatozas", r"forgalomkorlatoz|korlatoz|akadaly|elakad|tereles|lezar|baleset|muszaki hiba|fennakad|zavar|szunetel|egy vaganyon"),
    ("sztrajk", r"sztrajk|munkabeszuntet"),
    ("hev", r"\bhev\b|\bh[5-9]\b"),
    ("helyreallt", r"helyreall|\bvege a\b|vege a tereles|ujra kozlekedik|ujra kozlekednek|megszunt"),
]
_MAVINFORM_RE = [(c, re.compile(rx)) for c, rx in MAVINFORM_CATS]
_VOLAN_LOCK = threading.Lock()   # GTFS-csere / RSS-tár írás


def fold(s: Optional[str]) -> str:
    """Kis- és ékezet-független alak (keresés, kulcsszó)."""
    import unicodedata
    s = unicodedata.normalize("NFKD", (s or "").lower())
    return "".join(ch for ch in s if not unicodedata.combining(ch))


def bud_now() -> time.struct_time:
    try:
        from zoneinfo import ZoneInfo
        import datetime as _dt
        return _dt.datetime.now(ZoneInfo("Europe/Budapest")).timetuple()
    except Exception:
        return time.localtime()


def _json_write_atomic(path: Path, obj: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def _json_read(path: Path, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def volan_net_enabled(what: str = "any") -> bool:
    """what: gtfs / rss / any. KTMOCK: nincs kimenő hívás, csak ha a teszt helyi forrást (KT_VOLAN_GTFS_URL / KT_MAVINFORM_URL) ad."""
    if (os.environ.get("KT_VOLAN_DISABLE") or "").strip().lower() in {"1", "true", "yes"}:
        return False
    if not is_mock():
        return True
    g = bool(os.environ.get("KT_VOLAN_GTFS_URL"))
    r = bool(os.environ.get("KT_MAVINFORM_URL"))
    return g if what == "gtfs" else r if what == "rss" else (g or r)


def gtfs_meta() -> dict[str, Any]:
    return _json_read(VOLAN_GTFS_META, {})


def _gtfs_build_index(zpath: Path, db_tmp: Path) -> dict[str, Any]:
    """Könnyű, folyamos feldolgozás: routes/stops/agency/feed_info + számlálók. stop_times / shapes nem kerül memóriába."""
    import csv
    import gzip
    import io
    import zipfile
    info: dict[str, Any] = {}
    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
        for req in ("agency.txt", "routes.txt", "stops.txt", "trips.txt"):
            if req not in names:
                raise RuntimeError("gtfs_missing_%s" % req)

        def rows(name: str):
            with zf.open(name) as raw:
                yield from csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""))

        agencies = {r.get("agency_id") or "": (r.get("agency_name") or "").strip() for r in rows("agency.txt")}
        fi: dict[str, str] = {}
        if "feed_info.txt" in names:
            for r in rows("feed_info.txt"):
                fi = {k: (v or "") for k, v in r.items() if k}
                break
        trips_by_route: dict[str, int] = defaultdict(int)
        n_trips = 0
        for r in rows("trips.txt"):
            trips_by_route[r.get("route_id") or ""] += 1
            n_trips += 1
        n_st = None
        if "stop_times.txt" in names:
            n_st = -1  # fejléc
            with zf.open("stop_times.txt") as raw:
                while True:
                    b = raw.read(1 << 20)
                    if not b:
                        break
                    n_st += b.count(b"\n")
        if db_tmp.exists():
            db_tmp.unlink()
        conn = sqlite3.connect(db_tmp)
        try:
            conn.execute("PRAGMA journal_mode=OFF")
            conn.execute("PRAGMA synchronous=OFF")
            conn.execute("CREATE TABLE agency(id TEXT PRIMARY KEY, name TEXT)")
            conn.execute("CREATE TABLE routes(id TEXT PRIMARY KEY, short TEXT, long TEXT, type INTEGER, agency TEXT, network TEXT, color TEXT, ntrips INTEGER, fold TEXT)")
            conn.execute("CREATE TABLE stops(id TEXT PRIMARY KEY, name TEXT, lat REAL, lon REAL, loc INTEGER, parent TEXT, platform TEXT, fold TEXT)")
            conn.executemany("INSERT INTO agency VALUES(?,?)", list(agencies.items()))
            rgz = gzip.open(str(VOLAN_ROUTES_GZ) + ".tmp", "wt", encoding="utf-8")
            rgz.write('{"fields":["id","short","long","type","agency","network","ntrips"],"rows":[')
            batch: list[tuple] = []
            n_routes = 0
            for r in rows("routes.txt"):
                rid = r.get("route_id") or ""
                if not rid:
                    continue
                try:
                    rt = int(r.get("route_type") or 3)
                except ValueError:
                    rt = 3
                short = (r.get("route_short_name") or "").strip()
                long_ = (r.get("route_long_name") or "").strip()
                ag = r.get("agency_id") or ""
                net = (r.get("route_network") or "").strip()
                nt = trips_by_route.get(rid, 0)
                batch.append((rid, short, long_, rt, ag, net, (r.get("route_color") or ""), nt, fold(short + " " + long_)))
                rgz.write(("," if n_routes else "") + json.dumps([rid, short, long_, rt, ag, net, nt], ensure_ascii=False, separators=(",", ":")))
                n_routes += 1
            conn.executemany("INSERT OR REPLACE INTO routes VALUES(?,?,?,?,?,?,?,?,?)", batch)
            rgz.write('],"agency":' + json.dumps(agencies, ensure_ascii=False, separators=(",", ":")) + "}")
            rgz.close()
            del batch
            sgz = gzip.open(str(VOLAN_STOPS_GZ) + ".tmp", "wt", encoding="utf-8")
            sgz.write('{"fields":["id","name","lat","lon","loc","parent"],"rows":[')
            n_stops = 0
            sb: list[tuple] = []
            for r in rows("stops.txt"):
                sid = r.get("stop_id") or ""
                if not sid:
                    continue
                try:
                    lat = round(float(r.get("stop_lat") or "nan"), 6)
                    lon = round(float(r.get("stop_lon") or "nan"), 6)
                except ValueError:
                    continue
                if not (math.isfinite(lat) and math.isfinite(lon)):
                    continue
                try:
                    loc = int(r.get("location_type") or 0)
                except ValueError:
                    loc = 0
                name = (r.get("stop_name") or "").strip()
                par = r.get("parent_station") or ""
                sb.append((sid, name, lat, lon, loc, par, r.get("platform_code") or "", fold(name)))
                sgz.write(("," if n_stops else "") + json.dumps([sid, name, lat, lon, loc, par], ensure_ascii=False, separators=(",", ":")))
                n_stops += 1
                if len(sb) >= 5000:
                    conn.executemany("INSERT OR REPLACE INTO stops VALUES(?,?,?,?,?,?,?,?)", sb)
                    sb = []
            if sb:
                conn.executemany("INSERT OR REPLACE INTO stops VALUES(?,?,?,?,?,?,?,?)", sb)
            sgz.write("]}")
            sgz.close()
            conn.execute("CREATE INDEX idx_stops_lat ON stops(lat, lon)")
            conn.commit()
        finally:
            conn.close()
    info.update(
        {
            "feed_info": fi,
            "valid_from": fi.get("feed_start_date") or None,
            "valid_to": fi.get("feed_end_date") or None,
            "feed_version": fi.get("feed_version") or None,
            "counts": {"agency": len(agencies), "routes": n_routes, "stops": n_stops, "trips": n_trips, "stop_times": n_st},
            "agencies": [{"id": k, "name": v} for k, v in sorted(agencies.items())],
            "files": sorted(names),
        }
    )
    return info


def gtfs_update(force: bool = False) -> bool:
    """Napi letöltés: feltételes kérés (ETag/Last-Modified, ha van), lemezre folyamosan, ellenőrzés után atomi csere."""
    import hashlib
    import shutil
    VOLAN_DIR.mkdir(parents=True, exist_ok=True)
    old = gtfs_meta()
    try:
        free = shutil.disk_usage(VOLAN_DIR).free
        if free < VOLAN_MIN_FREE_BYTES:
            log("volan_gtfs_skip low_disk free_mb=%s" % (free // (1 << 20)))
            _gtfs_note(old, "low_disk")
            return False
    except Exception:
        pass
    part = VOLAN_DIR / "volanbusz_gtfs.zip.part"
    t0 = now()
    hdr = {"User-Agent": VOLAN_UA, "Accept": "application/zip"}
    if not force and VOLAN_GTFS_ZIP.exists():
        if old.get("etag"):
            hdr["If-None-Match"] = old["etag"]
        if old.get("last_modified"):
            hdr["If-Modified-Since"] = old["last_modified"]
    try:
        req = urllib.request.Request(VOLAN_GTFS_URL, headers=hdr)
        h = hashlib.sha256()
        size = 0
        try:
            resp = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as e:
            if e.code == 304 and (e.geturl() or VOLAN_GTFS_URL) == VOLAN_GTFS_URL:   # átirányítás utáni 304-et nem fogadunk el
                old["checked_at"] = now_ms()
                old["last_result"] = "not_modified"
                _json_write_atomic(VOLAN_GTFS_META, old)
                log("volan_gtfs not_modified")
                return True
            raise
        with resp, open(part, "wb") as f:
            etag = resp.headers.get("ETag") or ""
            lastmod = resp.headers.get("Last-Modified") or ""
            while True:
                b = resp.read(1 << 20)
                if not b:
                    break
                size += len(b)
                if size > VOLAN_GTFS_MAX_BYTES:
                    raise RuntimeError("gtfs_too_large")
                h.update(b)
                f.write(b)
        sha = h.hexdigest()
        dl_sec = round(now() - t0, 1)
        if sha == old.get("sha256") and VOLAN_GTFS_ZIP.exists() and VOLAN_GTFS_DB.exists():
            part.unlink()
            old.update({"checked_at": now_ms(), "last_result": "unchanged", "etag": etag, "last_modified": lastmod})
            _json_write_atomic(VOLAN_GTFS_META, old)
            log("volan_gtfs unchanged size=%s sec=%s" % (size, dl_sec))
            return True
        db_tmp = VOLAN_DIR / "gtfs_index.sqlite.tmp"
        info = _gtfs_build_index(part, db_tmp)   # hibás zip esetén itt elszáll → a régi marad
        with _VOLAN_LOCK:
            os.replace(part, VOLAN_GTFS_ZIP)
            os.replace(db_tmp, VOLAN_GTFS_DB)
            os.replace(str(VOLAN_ROUTES_GZ) + ".tmp", VOLAN_ROUTES_GZ)
            os.replace(str(VOLAN_STOPS_GZ) + ".tmp", VOLAN_STOPS_GZ)
            meta = {
                "source": VOLAN_GTFS_URL if VOLAN_GTFS_URL.startswith("http") else "local",
                "downloaded_at": now_ms(),
                "checked_at": now_ms(),
                "last_result": "updated",
                "last_error": None,
                "size": size,
                "sha256": sha,
                "etag": etag,
                "last_modified": lastmod,
                "download_sec": dl_sec,
                "index_sec": round(now() - t0 - dl_sec, 1),
            }
            meta.update(info)
            _json_write_atomic(VOLAN_GTFS_META, meta)
        c = info["counts"]
        log("volan_gtfs updated size=%s routes=%s stops=%s trips=%s valid=%s..%s sec=%s"
            % (size, c["routes"], c["stops"], c["trips"], info.get("valid_from"), info.get("valid_to"), round(now() - t0, 1)))
        return True
    except Exception as e:
        log("volan_gtfs_error err=%s %s" % (type(e).__name__, redact(str(e))[:120]))
        _gtfs_note(old, type(e).__name__)
        return False
    finally:
        for p in (part, VOLAN_DIR / "gtfs_index.sqlite.tmp", Path(str(VOLAN_ROUTES_GZ) + ".tmp"), Path(str(VOLAN_STOPS_GZ) + ".tmp")):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass


def _gtfs_note(meta: dict[str, Any], err: str) -> None:
    try:
        meta = dict(meta)
        meta["checked_at"] = now_ms()
        meta["last_result"] = "error"
        meta["last_error"] = err
        _json_write_atomic(VOLAN_GTFS_META, meta)
    except Exception:
        pass


def _rss_text(el: Any, tag: str) -> str:
    x = el.find(tag)
    return (x.text or "").strip() if x is not None and x.text else ""


def mavinform_cats(text: str) -> list[str]:
    t = " " + re.sub(r"[^a-z0-9]+", " ", fold(text)) + " "
    return [c for c, rx in _MAVINFORM_RE if rx.search(t)]


def mavinform_parse(raw: bytes) -> list[dict[str, Any]]:
    import xml.etree.ElementTree as ET
    from email.utils import parsedate_to_datetime
    if b"<!ENTITY" in raw[:4096].upper():
        raise RuntimeError("rss_entity_refused")
    root = ET.fromstring(raw)
    items = []
    for it in root.iter("item"):
        title = _rss_text(it, "title")
        link = _rss_text(it, "link")
        guid = _rss_text(it, "guid") or link
        desc_raw = _rss_text(it, "description")
        desc = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", desc_raw)).strip()[:2000]
        pub = _rss_text(it, "pubDate")
        ts = None
        try:
            ts = int(parsedate_to_datetime(pub).timestamp() * 1000) if pub else None
        except Exception:
            ts = None
        if not (guid or title):
            continue
        items.append({"id": guid or link or title, "title": title, "link": link, "pubDate": pub, "ts": ts,
                      "description": desc, "cats": mavinform_cats(title + " " + desc)})
    return items


def mavinform_poll() -> bool:
    VOLAN_DIR.mkdir(parents=True, exist_ok=True)
    store = _json_read(MAVINFORM_STORE, {})
    hdr = {"User-Agent": VOLAN_UA, "Accept": "application/rss+xml, application/xml;q=0.9"}
    if store.get("etag"):
        hdr["If-None-Match"] = store["etag"]
    if store.get("last_modified"):
        hdr["If-Modified-Since"] = store["last_modified"]
    try:
        try:
            with urllib.request.urlopen(urllib.request.Request(MAVINFORM_URL, headers=hdr), timeout=30) as resp:
                raw = resp.read(MAVINFORM_MAX_BYTES + 1)
                etag = resp.headers.get("ETag") or ""
                lastmod = resp.headers.get("Last-Modified") or ""
        except urllib.error.HTTPError as e:
            if e.code == 304 and (e.geturl() or MAVINFORM_URL) == MAVINFORM_URL:
                store["checked_at"] = now_ms()
                store["last_error"] = None
                with _VOLAN_LOCK:
                    _json_write_atomic(MAVINFORM_STORE, store)
                return True
            raise
        if len(raw) > MAVINFORM_MAX_BYTES:
            raise RuntimeError("rss_too_large")
        fresh = mavinform_parse(raw)
        with _VOLAN_LOCK:
            store = _json_read(MAVINFORM_STORE, {})
            items = {x["id"]: x for x in (store.get("items") or []) if isinstance(x, dict) and x.get("id")}
            t_now = now_ms()
            added = 0
            for x in fresh:
                if x["id"] in items:
                    prev = items[x["id"]]
                    if prev.get("title") != x["title"] or prev.get("description") != x["description"]:
                        x["first_seen"] = prev.get("first_seen") or t_now
                        x["updated_seen"] = t_now
                        items[x["id"]] = x
                    continue
                x["first_seen"] = t_now
                items[x["id"]] = x
                added += 1
            cutoff = t_now - MAVINFORM_MAX_DAYS * 86400 * 1000
            lst = [x for x in items.values() if (x.get("ts") or x.get("first_seen") or t_now) >= cutoff]
            lst.sort(key=lambda x: x.get("ts") or x.get("first_seen") or 0, reverse=True)
            lst = lst[:MAVINFORM_MAX_ITEMS]
            store = {"items": lst, "checked_at": t_now, "last_ok": t_now, "last_error": None,
                     "etag": etag, "last_modified": lastmod, "feed_items": len(fresh)}
            _json_write_atomic(MAVINFORM_STORE, store)
        if added:
            log("mavinform new=%s total=%s" % (added, len(lst)))
        return True
    except Exception as e:
        log("mavinform_error err=%s" % type(e).__name__)
        try:
            with _VOLAN_LOCK:
                st = _json_read(MAVINFORM_STORE, {})
                st["checked_at"] = now_ms()
                st["last_error"] = type(e).__name__
                _json_write_atomic(MAVINFORM_STORE, st)
        except Exception:
            pass
        return False


def volan_worker() -> None:
    """Saját szál: MÁVINFORM 5 percenként, Volán GTFS naponta (KT_VOLAN_GTFS_AT, Budapest) + induláskor, ha hiányzik / >24 óra."""
    assert STATE is not None
    if not volan_net_enabled():
        log("volan_worker off (mock or KT_VOLAN_DISABLE)")
        return
    if STATE.stop.wait(20):   # induláskor ne a flotta-lekéréssel versenyezzen
        return
    last_rss = 0.0
    last_gtfs_day = ""
    try:
        hh, mm = [int(x) for x in VOLAN_GTFS_AT.split(":", 1)]
    except Exception:
        hh, mm = 3, 30
    do_gtfs = volan_net_enabled("gtfs")
    do_rss = volan_net_enabled("rss")
    gtfs_th: Optional[threading.Thread] = None
    m = gtfs_meta()
    if do_gtfs and (not VOLAN_GTFS_ZIP.exists() or not VOLAN_GTFS_DB.exists()
                    or now_ms() - int(m.get("downloaded_at") or 0) > VOLAN_GTFS_MAX_AGE * 1000):
        gtfs_th = threading.Thread(target=gtfs_update, name="kt-volan-gtfs", daemon=True)
        gtfs_th.start()
    bt = bud_now()
    if bt.tm_hour * 60 + bt.tm_min >= hh * 60 + mm:
        # a mai időpont már elmúlt: ma nincs újabb ütemezett letöltés (induláskor a fenti 24 órás szabály dönt)
        last_gtfs_day = time.strftime("%Y-%m-%d", bt)
    while not STATE.stop.is_set():
        try:
            if do_rss and now() - last_rss >= MAVINFORM_EVERY:
                last_rss = now()
                mavinform_poll()
            bt = bud_now()
            day = time.strftime("%Y-%m-%d", bt)
            if do_gtfs and day != last_gtfs_day and bt.tm_hour * 60 + bt.tm_min >= hh * 60 + mm:
                last_gtfs_day = day
                if gtfs_th is None or not gtfs_th.is_alive():
                    gtfs_th = threading.Thread(target=gtfs_update, name="kt-volan-gtfs", daemon=True)
                    gtfs_th.start()
        except Exception:
            log("volan_worker_error " + redact(traceback.format_exc().splitlines()[-1]))
        STATE.stop.wait(15)


def _volan_db() -> Optional[sqlite3.Connection]:
    if not VOLAN_GTFS_DB.exists():
        return None
    conn = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(str(VOLAN_GTFS_DB)), uri=True, timeout=5)
    return conn


def _int_param(params: dict[str, list[str]], name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(float(first(params, name) or default))
    except ValueError:
        v = default
    return max(lo, min(hi, v))


def volan_status() -> dict[str, Any]:
    m = gtfs_meta()
    st = _json_read(MAVINFORM_STORE, {})
    keep = ("source", "downloaded_at", "checked_at", "last_result", "last_error", "size", "sha256", "download_sec",
            "index_sec", "valid_from", "valid_to", "feed_version", "feed_info", "counts", "agencies")
    return {
        "status": "OK",
        "now": now_ms(),
        "enabled": {"gtfs": volan_net_enabled("gtfs"), "mavinform": volan_net_enabled("rss")},
        "schedule": {"gtfs_daily_at": VOLAN_GTFS_AT + " Europe/Budapest", "mavinform_every_sec": MAVINFORM_EVERY},
        "gtfs": ({k: m.get(k) for k in keep} if m else None),
        "gtfs_ready": VOLAN_GTFS_DB.exists(),
        "mavinform": {"n": len(st.get("items") or []), "checked_at": st.get("checked_at"), "last_ok": st.get("last_ok"),
                      "last_error": st.get("last_error")},
    }


def volan_routes(params: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
    conn = _volan_db()
    if conn is None:
        return 503, {"status": "NO_DATA", "text": "volan gtfs not downloaded yet"}
    try:
        limit = _int_param(params, "limit", 5000, 1, 5000)
        where, args = [], []
        words = re.findall(r"[a-z0-9]+", fold(first(params, "q") or ""))[:6]
        if words:
            where.append("((" + " AND ".join(["fold LIKE ?"] * len(words)) + ") OR short = ?)")
            args += ["%" + w + "%" for w in words] + [(first(params, "q") or "").strip()]
        ag = (first(params, "agency") or "").strip()
        if ag:
            where.append("agency = ?")
            args.append(ag)
        net = (first(params, "network") or "").strip()
        if net:
            where.append("network = ?")
            args.append(net)
        sql = "SELECT id, short, long, type, agency, network, ntrips FROM routes" + (" WHERE " + " AND ".join(where) if where else "")
        total = conn.execute("SELECT COUNT(*) FROM (" + sql + ")", args).fetchone()[0]
        rows = conn.execute(sql + " ORDER BY short, id LIMIT ?", args + [limit]).fetchall()
        agn = dict(conn.execute("SELECT id, name FROM agency").fetchall())
    finally:
        conn.close()
    lst = [{"id": r[0], "short": r[1], "long": r[2], "type": r[3], "agency": r[4], "agencyName": agn.get(r[4], ""),
            "network": r[5], "ntrips": r[6]} for r in rows]
    m = gtfs_meta()
    return 200, {"status": "OK", "now": now_ms(), "feed_version": m.get("feed_version"), "valid_to": m.get("valid_to"),
                 "total": total, "n": len(lst), "list": lst}


def volan_stops(params: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
    conn = _volan_db()
    if conn is None:
        return 503, {"status": "NO_DATA", "text": "volan gtfs not downloaded yet"}
    try:
        limit = _int_param(params, "limit", 2000, 1, 5000)
        where, args = [], []
        bbox = (first(params, "bbox") or "").strip()
        if bbox:
            try:
                a = [float(x) for x in bbox.split(",")]
                if len(a) != 4 or not all(math.isfinite(x) for x in a):
                    raise ValueError
            except ValueError:
                return 400, {"status": "ERROR", "text": "bbox=minLon,minLat,maxLon,maxLat"}
            where.append("lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?")
            args += [min(a[1], a[3]), max(a[1], a[3]), min(a[0], a[2]), max(a[0], a[2])]
        for w in re.findall(r"[a-z0-9]+", fold(first(params, "q") or ""))[:6]:
            where.append("fold LIKE ?")
            args.append("%" + w + "%")
        if (first(params, "stations") or "") in ("1", "true"):
            where.append("loc = 1")
        sql = "SELECT id, name, lat, lon, loc, parent, platform FROM stops" + (" WHERE " + " AND ".join(where) if where else "")
        total = conn.execute("SELECT COUNT(*) FROM (" + sql + ")", args).fetchone()[0]
        rows = conn.execute(sql + " ORDER BY name, id LIMIT ?", args + [limit]).fetchall()
    finally:
        conn.close()
    lst = [{"id": r[0], "name": r[1], "lat": r[2], "lon": r[3], "loc": r[4], "parent": r[5] or None, "platform": r[6] or None} for r in rows]
    return 200, {"status": "OK", "now": now_ms(), "total": total, "n": len(lst), "truncated": total > len(lst), "list": lst}


def mavinform_query(params: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
    st = _json_read(MAVINFORM_STORE, {})
    items = list(st.get("items") or [])
    since_s = (first(params, "since") or "").strip()
    if since_s:
        since = None
        try:
            v = float(since_s)
            since = int(v * 1000) if v < 1e11 else int(v)   # mp vagy ms
        except ValueError:
            try:
                import datetime as _dt
                d = _dt.datetime.fromisoformat(since_s.replace("Z", "+00:00"))
                if d.tzinfo is None:
                    try:
                        from zoneinfo import ZoneInfo
                        d = d.replace(tzinfo=ZoneInfo("Europe/Budapest"))
                    except Exception:
                        pass
                since = int(d.timestamp() * 1000)
            except ValueError:
                return 400, {"status": "ERROR", "text": "since: epoch s/ms or ISO date"}
        items = [x for x in items if (x.get("ts") or x.get("first_seen") or 0) >= since]
    cats = [c.strip() for c in (first(params, "cat") or "").split(",") if c.strip()]
    if cats:
        items = [x for x in items if set(cats) & set(x.get("cats") or [])]
    limit = _int_param(params, "limit", 200, 1, MAVINFORM_MAX_ITEMS)
    return 200, {"status": "OK", "now": now_ms(), "checked_at": st.get("checked_at"), "last_error": st.get("last_error"),
                 "categories": [c for c, _ in MAVINFORM_CATS], "n": min(len(items), limit), "total": len(items), "list": items[:limit]}


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
                return self._send_fleet(params)
            if path == "/history":
                return self._send_history(params)
            if path == "/lastknown":
                return self._send_lastknown(params)
            if path == "/offline":
                return self._send_offline(params)
            if path == "/depots":  # KKMD-4
                return self._send_json(200, {"status": "OK", "now": now_ms(), "depots": ktdepot.list_depots(STATE.db, STATE.db_lock)})
            if path == "/depot/candidates":
                return self._send_json(200, {"status": "OK", "now": now_ms(), "candidates": ktdepot.list_candidates(STATE.db, STATE.db_lock)})
            # srv-volan1: Volán GTFS + MÁVINFORM (csak olvasás)
            if path == "/api/volan/gtfs/status":
                return self._send_json(200, volan_status())
            if path == "/api/volan/routes":
                return self._send_json(*volan_routes(params))
            if path == "/api/volan/stops":
                return self._send_json(*volan_stops(params))
            if path == "/api/mavinform":
                return self._send_json(*mavinform_query(params))

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
            if path in ("/depot/approve", "/depot/rename", "/depot/delete"):  # KKMD-4 (tokenes írás)
                STATE.mark_client()
                try:
                    body = json.loads(raw.decode("utf-8") or "{}")
                except Exception:
                    return self._send_json(400, {"status": "ERROR", "text": "invalid json"})
                if not isinstance(body, dict):
                    return self._send_json(400, {"status": "ERROR", "text": "invalid json"})
                code, obj = ktdepot.write(STATE.db, STATE.db_lock, path, body, now_ms())
                log("depot_write path=%s code=%s" % (path, code))
                return self._send_json(code, obj)
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

    def _send_fleet(self, params: Optional[dict[str, list[str]]] = None) -> None:
        assert STATE is not None
        # KKMD-18: /fleet?extra=1 → csak az idegen rendszámú Volán buszok (az előtagos lekérdezések ezeket nem adják vissza)
        only_extra = (first(params or {}, "extra") or "") in ("1", "true")
        snap = STATE.fleet.snapshot(only_extra=only_extra)
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
        body = {"status": "OK", "plate": norm_plate(plate), "n": len(rows), "points": rows}
        if norm_plate(plate) in volan_extra_plates():
            body["volanExtra"] = True  # KKMD-18
        self._send_json(200, body)

    def _send_lastknown(self, params: dict[str, list[str]]) -> None:
        def num(name: str) -> Optional[float]:
            s = first(params, name)
            if s is None or s == "":
                return None
            try:
                v = float(s)
            except ValueError:
                return None
            return v if math.isfinite(v) else None
        plate = first(params, "plate") or ""
        if plate:
            o = lastknown_plate(plate)
            return self._send_json(200, {"status": "OK", "now": now_ms(), "plate": norm_plate(plate), "found": bool(o), "point": o})
        lat, lon = num("lat"), num("lon")
        if lat is None or lon is None or not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            return self._send_json(400, {"status": "ERROR", "text": "lat, lon required"})
        r = num("r")
        r = LASTKNOWN_R_DEFAULT if r is None or r <= 0 else min(r, LASTKNOWN_R_MAX)
        ma = num("maxage")
        rows = lastknown_query(lat, lon, r, int(ma) if ma and ma > 0 else None)
        self._send_json(200, {"status": "OK", "now": now_ms(), "r": int(r), "n": len(rows), "list": rows})

    def _send_offline(self, params: dict[str, list[str]]) -> None:
        s = first(params, "minage")
        try:
            minage = int(float(s)) if s not in (None, "") else 3600
        except ValueError:
            minage = 3600
        minage = max(0, minage)
        with STATE.db_lock:
            since = STATE.db.execute("SELECT MIN(first_seen) FROM plate_last").fetchone()[0]
        rows = offline_query(minage)
        self._send_json(200, {"status": "OK", "now": now_ms(), "minage": minage, "since": since, "n": len(rows), "list": rows})

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
    vw = threading.Thread(target=volan_worker, name="kt-volan", daemon=True)
    vw.start()
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
