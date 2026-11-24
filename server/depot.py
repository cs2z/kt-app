"""KKMD-4 – tárolók (depók) gyűjtése és jóváhagyása. Csak stdlib; a server.py hívja.

Táblák (fleet.sqlite, CREATE IF NOT EXISTS – automatikus migráció induláskor):
  night_pos       éjszakai helyek 23:00–03:00 (Budapest): élő (a meglévő flotta-pollból) + a kikapcsolt buszok utolsó ismert helye
                  (plate_last-ból). 30 nap után törlődik (KT_NIGHT_DAYS).
  depot_candidate jelölt tárolók (éjszaka végi helyek klaszterei); status: new / approved / deleted
  depot           jóváhagyott tárolók (id, név, középpont, sugár)
  plate_depot     buszonként az utolsó tároló-hozzárendelés – nem törlődik
  depot_meta      kulcs-érték (utolsó éjszakai futás)
Nincs külön BKK-hívás: csak a már lekért flotta-adatot és a plate_last táblát használja.
"""
from __future__ import annotations

import datetime as _dt
import json
import math
import os
import time
from typing import Any, Callable, Optional

NIGHT_DAYS = int(os.environ.get("KT_NIGHT_DAYS", "30"))        # nyers éjszakai helyek megőrzése (Zoltán: 1 hónap)
CLUSTER_R = float(os.environ.get("KT_DEPOT_R", "175"))           # klaszter sugár, m (150–200)
MIN_BUSES = int(os.environ.get("KT_DEPOT_MIN_BUSES", "3"))       # jelölthöz legalább ennyi különböző busz
MIN_NIGHTS = int(os.environ.get("KT_DEPOT_MIN_NIGHTS", "3"))     # … legalább ennyi különböző éjszakán
CLUSTER_NIGHTS = int(os.environ.get("KT_DEPOT_NIGHTS", "14"))    # ennyi legutóbbi éjszaka éjszaka végi helyét klaszterezi
LIVE_EVERY_MS = 10 * 60 * 1000   # élő busz: legfeljebb 10 percenként egy sor (vagy ha > 100 m-t mozdult)
OFF_EVERY_S = 10 * 60            # kikapcsolt buszok utolsó helye: 10 percenként pillanatkép
OFF_AFTER_MS = 15 * 60 * 1000    # ennél régebbi saját jel = nincs friss jel (OFF)
OFF_MAX_AGE_MS = 48 * 3600 * 1000
JOB_HM = (3, 15)                 # éjszakai klaszterezés: 03:15 után, naponta egyszer
NAME_MAX = 40

_last_live: dict[str, tuple[int, float, float]] = {}
_last_off_snap = 0.0


def _bud(ts_s: float) -> _dt.datetime:
    try:
        from zoneinfo import ZoneInfo
        return _dt.datetime.fromtimestamp(ts_s, ZoneInfo("Europe/Budapest"))
    except Exception:
        return _dt.datetime.fromtimestamp(ts_s)


def night_of(ts_ms: int) -> Optional[str]:
    """23:00–03:00 helyi idő → az éjszaka kezdő napja (YYYY-MM-DD), egyébként None."""
    d = _bud(ts_ms / 1000.0)
    if d.hour >= 23:
        return d.strftime("%Y-%m-%d")
    if d.hour < 3:
        return (d - _dt.timedelta(days=1)).strftime("%Y-%m-%d")
    return None


def dist_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def init_db(conn: Any) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS night_pos (plate TEXT NOT NULL, ts INTEGER NOT NULL, night TEXT NOT NULL, sig INTEGER, "
        "lat REAL NOT NULL, lon REAL NOT NULL, trip TEXT, off INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (plate, ts))"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_night_pos_night ON night_pos(night, plate, ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_night_pos_ts ON night_pos(ts)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS depot_candidate (id INTEGER PRIMARY KEY AUTOINCREMENT, lat REAL NOT NULL, lon REAL NOT NULL, "
        "radius REAL NOT NULL, buses INTEGER NOT NULL, nights INTEGER NOT NULL, plates TEXT, first_night TEXT, last_night TEXT, "
        "status TEXT NOT NULL DEFAULT 'new', created INTEGER NOT NULL, updated INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS depot (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, lat REAL NOT NULL, lon REAL NOT NULL, "
        "radius REAL NOT NULL, cand_id INTEGER, created INTEGER NOT NULL, updated INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS plate_depot (plate TEXT PRIMARY KEY, depot_id INTEGER NOT NULL, last_seen INTEGER NOT NULL, "
        "night TEXT, updated INTEGER NOT NULL)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_plate_depot_depot ON plate_depot(depot_id)")
    conn.execute("CREATE TABLE IF NOT EXISTS depot_meta (k TEXT PRIMARY KEY, v TEXT)")
    conn.commit()


# ---------- gyűjtés ----------
def record_live(conn: Any, lock: Any, lst: list[dict[str, Any]], poll_ms: int, norm_plate: Callable, signal_ms: Callable) -> int:
    """A flotta-poll járművei (a meglévő hívásból) – csak éjszaka, buszonként ritkítva."""
    night = night_of(poll_ms)
    if not night:
        return 0
    rows = []
    for v in lst:
        p = norm_plate(v.get("licensePlate"))
        loc = v.get("location") or {}
        try:
            lat, lon = float(loc.get("lat")), float(loc.get("lon"))
        except (TypeError, ValueError):
            continue
        if not p:
            continue
        sig, _ = signal_ms(v, poll_ms)
        prev = _last_live.get(p)
        if prev and poll_ms - prev[0] < LIVE_EVERY_MS and dist_m(prev[1], prev[2], lat, lon) < 100:
            continue
        _last_live[p] = (poll_ms, lat, lon)
        off = 1 if poll_ms - sig > OFF_AFTER_MS else 0
        rows.append((p, poll_ms, night, sig, lat, lon, v.get("tripId") or "", off))
    if rows:
        with lock:
            conn.executemany("INSERT OR IGNORE INTO night_pos(plate,ts,night,sig,lat,lon,trip,off) VALUES (?,?,?,?,?,?,?,?)", rows)
            conn.commit()
    return len(rows)


def snapshot_off(conn: Any, lock: Any, now_ms: int, force: bool = False) -> int:
    """A kikapcsolt / FUTÁR-ból kiesett buszok utolsó ismert helye (plate_last) – éjszaka 10 percenként."""
    global _last_off_snap
    night = night_of(now_ms)
    if not night or (not force and time.time() - _last_off_snap < OFF_EVERY_S):
        return 0
    _last_off_snap = time.time()
    with lock:
        R = conn.execute(
            "SELECT plate, ts, lat, lon, trip FROM plate_last WHERE ts < ? AND ts > ? AND lat IS NOT NULL AND lon IS NOT NULL",
            (now_ms - OFF_AFTER_MS, now_ms - OFF_MAX_AGE_MS),
        ).fetchall()
        rows = [(r[0], now_ms, night, r[1], r[2], r[3], "", 1) for r in R]
        conn.executemany("INSERT OR IGNORE INTO night_pos(plate,ts,night,sig,lat,lon,trip,off) VALUES (?,?,?,?,?,?,?,?)", rows)
        conn.commit()
    return len(rows)


def prune(conn: Any, lock: Any, now_ms: int) -> int:
    with lock:
        cur = conn.execute("DELETE FROM night_pos WHERE ts < ?", (now_ms - NIGHT_DAYS * 86400000,))
        conn.commit()
        return cur.rowcount or 0


# ---------- éjszakai feldolgozás ----------
def end_points(conn: Any, nights: Optional[int] = None) -> list[tuple[str, str, int, float, float]]:
    """(plate, night, sig, lat, lon): buszonként és éjszakánként az utolsó hely, ha akkor nem volt menetben (parkol)."""
    q = ("SELECT n.plate, n.night, n.sig, n.lat, n.lon, n.trip FROM night_pos n JOIN "
         "(SELECT plate, night, MAX(ts) mt FROM night_pos GROUP BY plate, night) m ON m.plate=n.plate AND m.night=n.night AND m.mt=n.ts")
    R = conn.execute(q).fetchall()
    if nights:
        keep = set(sorted({r[1] for r in R})[-nights:])
        R = [r for r in R if r[1] in keep]
    return [(r[0], r[1], int(r[2] or 0), float(r[3]), float(r[4])) for r in R if not r[5]]


def cluster(pts: list[tuple[str, str, int, float, float]], r: float = CLUSTER_R) -> list[dict[str, Any]]:
    """Egyszerű sűrűség-alapú csoportosítás r sugarú szomszédsággal (rács-gyorsítás)."""
    if not pts:
        return []
    cell = r / 111000.0
    grid: dict[tuple[int, int], list[int]] = {}
    for i, p in enumerate(pts):
        grid.setdefault((int(p[3] // cell), int(p[4] // (cell * 1.5))), []).append(i)

    def near(lat: float, lon: float) -> list[int]:
        gy, gx = int(lat // cell), int(lon // (cell * 1.5))
        out = []
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                for j in grid.get((gy + dy, gx + dx), ()):
                    if dist_m(lat, lon, pts[j][3], pts[j][4]) <= r:
                        out.append(j)
        return out

    dens = sorted(range(len(pts)), key=lambda i: -len(near(pts[i][3], pts[i][4])))
    used: set[int] = set()
    out = []
    for i in dens:
        if i in used:
            continue
        mem = [j for j in near(pts[i][3], pts[i][4]) if j not in used]
        for _ in range(2):  # középpont finomítása
            lat = sum(pts[j][3] for j in mem) / len(mem)
            lon = sum(pts[j][4] for j in mem) / len(mem)
            m2 = [j for j in near(lat, lon) if j not in used]
            if not m2:
                break
            mem = m2
        used.update(mem)
        lat = sum(pts[j][3] for j in mem) / len(mem)
        lon = sum(pts[j][4] for j in mem) / len(mem)
        ds = sorted(dist_m(lat, lon, pts[j][3], pts[j][4]) for j in mem)
        rad = max(50.0, min(r, ds[int(0.9 * (len(ds) - 1))] + 25)) if ds else r
        out.append({"lat": lat, "lon": lon, "radius": round(rad, 1), "plates": sorted({pts[j][0] for j in mem}),
                    "nights": sorted({pts[j][1] for j in mem})})
    return out


def run_job(conn: Any, lock: Any, now_ms: int) -> dict[str, Any]:
    """Klaszterezés → depot_candidate; plate_depot frissítés; régi sorok törlése."""
    pruned = prune(conn, lock, now_ms)
    with lock:
        pts = end_points(conn, CLUSTER_NIGHTS)
        C = cluster(pts)
        deps = conn.execute("SELECT id, lat, lon, radius FROM depot").fetchall()
        cands = conn.execute("SELECT id, lat, lon, radius, status FROM depot_candidate").fetchall()
        new = upd = 0
        for c in C:
            if len(c["plates"]) < MIN_BUSES or len(c["nights"]) < MIN_NIGHTS:
                continue
            if any(dist_m(c["lat"], c["lon"], d[1], d[2]) <= max(CLUSTER_R, d[3]) for d in deps):
                continue
            hit = next((k for k in cands if dist_m(c["lat"], c["lon"], k[1], k[2]) <= CLUSTER_R), None)
            vals = (c["lat"], c["lon"], c["radius"], len(c["plates"]), len(c["nights"]), json.dumps(c["plates"]), c["nights"][0], c["nights"][-1], now_ms)
            if hit:
                if hit[4] == "new":
                    conn.execute("UPDATE depot_candidate SET lat=?,lon=?,radius=?,buses=?,nights=?,plates=?,first_night=?,last_night=?,updated=? WHERE id=?", vals + (hit[0],))
                    upd += 1
                continue  # jóváhagyott / törölt helyen nem javasol újra
            conn.execute("INSERT INTO depot_candidate(lat,lon,radius,buses,nights,plates,first_night,last_night,updated,status,created) "
                         "VALUES (?,?,?,?,?,?,?,?,?,'new',?)", vals + (now_ms,))
            new += 1
        conn.commit()
    assigned = assign_plates(conn, lock, now_ms)
    with lock:
        conn.execute("INSERT OR REPLACE INTO depot_meta(k,v) VALUES ('last_job', ?)", (json.dumps({"ts": now_ms, "points": len(pts), "clusters": len(C), "new": new, "updated": upd, "assigned": assigned, "pruned": pruned}),))
        conn.commit()
    return {"points": len(pts), "clusters": len(C), "new": new, "updated": upd, "assigned": assigned, "pruned": pruned}


def assign_plates(conn: Any, lock: Any, now_ms: int) -> int:
    """Buszonként a legutolsó éjszaka végi parkoló hely → az azt tartalmazó jóváhagyott tároló (plate_depot, nem törlődik)."""
    with lock:
        deps = conn.execute("SELECT id, lat, lon, radius FROM depot").fetchall()
        if not deps:
            return 0
        last: dict[str, tuple[str, int, float, float]] = {}
        for p, night, sig, lat, lon in end_points(conn):
            if p not in last or (night, sig) > (last[p][0], last[p][1]):
                last[p] = (night, sig, lat, lon)
        n = 0
        for p, (night, sig, lat, lon) in last.items():
            best = None
            for d in deps:
                x = dist_m(lat, lon, d[1], d[2])
                if x <= d[3] and (best is None or x < best[1]):
                    best = (d[0], x)
            if best:
                conn.execute("INSERT INTO plate_depot(plate,depot_id,last_seen,night,updated) VALUES (?,?,?,?,?) "
                             "ON CONFLICT(plate) DO UPDATE SET depot_id=excluded.depot_id,last_seen=excluded.last_seen,night=excluded.night,updated=excluded.updated "
                             "WHERE excluded.night >= COALESCE(plate_depot.night,'')", (p, best[0], sig, night, now_ms))
                n += 1
        conn.commit()
        return n


def tick(conn: Any, lock: Any, now_ms: int, log: Callable[[str], None]) -> None:
    """A szerver ütemezője hívja minden körben (olcsó): éjszakai OFF-pillanatkép, 03:15-ös napi futás."""
    snapshot_off(conn, lock, now_ms)
    d = _bud(now_ms / 1000.0)
    if (d.hour, d.minute) < JOB_HM or d.hour >= 5:
        return
    day = d.strftime("%Y-%m-%d")
    with lock:
        r = conn.execute("SELECT v FROM depot_meta WHERE k='job_day'").fetchone()
    if r and r[0] == day:
        return
    with lock:
        conn.execute("INSERT OR REPLACE INTO depot_meta(k,v) VALUES ('job_day', ?)", (day,))
        conn.commit()
    res = run_job(conn, lock, now_ms)
    log("depot_job " + " ".join("%s=%s" % kv for kv in res.items()))


# ---------- végpontok ----------
def list_candidates(conn: Any, lock: Any) -> list[dict[str, Any]]:
    with lock:
        R = conn.execute("SELECT id, lat, lon, radius, buses, nights, plates, first_night, last_night, updated FROM depot_candidate "
                         "WHERE status='new' ORDER BY buses DESC, nights DESC").fetchall()
    return [{"id": r[0], "lat": r[1], "lon": r[2], "radius": r[3], "buses": r[4], "nights": r[5], "plates": json.loads(r[6] or "[]"),
             "firstNight": r[7], "lastNight": r[8], "updated": r[9]} for r in R]


def list_depots(conn: Any, lock: Any) -> list[dict[str, Any]]:
    with lock:
        D = conn.execute("SELECT id, name, lat, lon, radius FROM depot ORDER BY name").fetchall()
        P = conn.execute("SELECT d.depot_id, d.plate, d.last_seen, d.night, l.ts, l.lat, l.lon FROM plate_depot d "
                         "LEFT JOIN plate_last l ON l.plate=d.plate ORDER BY d.plate").fetchall()
    by: dict[int, list[dict[str, Any]]] = {}
    for r in P:
        by.setdefault(r[0], []).append({"plate": r[1], "lastSeen": r[2], "night": r[3], "ts": r[4], "lat": r[5], "lon": r[6]})
    return [{"id": d[0], "name": d[1], "lat": d[2], "lon": d[3], "radius": d[4], "plates": by.get(d[0], [])} for d in D]


def _name(s: Any) -> Optional[str]:
    s = " ".join(str(s or "").split())
    return s if 0 < len(s) <= NAME_MAX else None


def write(conn: Any, lock: Any, path: str, body: dict[str, Any], now_ms: int) -> tuple[int, dict[str, Any]]:
    """POST /depot/approve {id, name} · /depot/rename {id, name} · /depot/delete {id}"""
    try:
        i = int(body.get("id"))
    except (TypeError, ValueError):
        return 400, {"status": "ERROR", "text": "invalid id"}
    if path == "/depot/approve":
        nm = _name(body.get("name"))
        if not nm:
            return 400, {"status": "ERROR", "text": "invalid name"}
        with lock:
            c = conn.execute("SELECT lat, lon, radius, status FROM depot_candidate WHERE id=?", (i,)).fetchone()
            if not c or c[3] != "new":
                return 404, {"status": "NOT_FOUND", "text": "no such candidate"}
            cur = conn.execute("INSERT INTO depot(name,lat,lon,radius,cand_id,created,updated) VALUES (?,?,?,?,?,?,?)", (nm, c[0], c[1], c[2], i, now_ms, now_ms))
            conn.execute("UPDATE depot_candidate SET status='approved', updated=? WHERE id=?", (now_ms, i))
            conn.commit()
            did = cur.lastrowid
        assign_plates(conn, lock, now_ms)
        return 200, {"status": "OK", "id": did}
    if path == "/depot/rename":
        nm = _name(body.get("name"))
        if not nm:
            return 400, {"status": "ERROR", "text": "invalid name"}
        with lock:
            cur = conn.execute("UPDATE depot SET name=?, updated=? WHERE id=?", (nm, now_ms, i))
            conn.commit()
        return (200, {"status": "OK"}) if cur.rowcount else (404, {"status": "NOT_FOUND", "text": "no such depot"})
    if path == "/depot/delete":
        with lock:
            d = conn.execute("SELECT cand_id FROM depot WHERE id=?", (i,)).fetchone()
            if not d:
                return 404, {"status": "NOT_FOUND", "text": "no such depot"}
            conn.execute("DELETE FROM depot WHERE id=?", (i,))
            conn.execute("DELETE FROM plate_depot WHERE depot_id=?", (i,))
            if d[0]:
                conn.execute("UPDATE depot_candidate SET status='deleted', updated=? WHERE id=?", (now_ms, d[0]))
            conn.commit()
        return 200, {"status": "OK"}
    return 404, {"status": "NOT_FOUND", "text": "unknown path"}
