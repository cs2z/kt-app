# KT köztes szerver (nyilvános repo: `server/`)

A VOLÁN Agglo Bp. – KT app BKK FUTÁR / GTFS-RT hívásait ez a Python-szerver
gyorsítótározza és szolgálja ki. A BKK-kulcs csak a VPS-en van.

Ez a könyvtár **nem tartalmazhat** titkokat, tokent, naplót vagy adatbázist.

## Telepítés a VPS-en

Lásd a `deploy/TELEPITES.md` leírást. Egy parancs, rootként:

```bash
curl -fsSL https://cs2z.github.io/kt-app/server/install.sh | bash
```

Tartalék, ha a Pages még 404-et ad:

```bash
curl -fsSL https://raw.githubusercontent.com/cs2z/kt-app/main/server/install.sh | bash
```

A script 10 percenként `git pull`-lal frissül (`kt-update.timer`). Ha a
`server/` könyvtár változott, a `kt-server` szolgáltatás újraindul.

## Fájlok

| Fájl | Szerep |
|---|---|
| `install.sh` | egyszeri, idempotens telepítő |
| `server.py` | a proxy (Python 3, csak standard könyvtár) |
| `kt-set-domain` | Caddy-hoszt cseréje (`sudo kt-set-domain ktbp.hu`) |
| `kt-update.sh` | GitHub-frissítés |
| `systemd/` | `kt-server.service`, `kt-update.service`, `kt-update.timer` |
| `requirements.txt` | jelenleg üres (stdlib) |

## Helyi próba (fejlesztés, nem a VPS)

```bash
export KT_MOCK=1
export KT_CLIENT_TOKEN=dev-token
export KT_BIND=127.0.0.1 KT_PORT=8788
export KT_DATA_DIR=/tmp/kt-mock-data KT_LOG_DIR=/tmp/kt-mock-logs
python3 server.py
# másik terminálban:
curl -s http://127.0.0.1:8788/health
curl -s -H "X-KT-Token: dev-token" http://127.0.0.1:8788/fleet
```

A `KT_MOCK=1` (vagy `BKK_API_KEY` értéke `KTMOCK…`) mellett a szerver nem
hívja a BKK-t.

## Végpontok (v1.04 kliens)

Minden végpont – a `/health` kivételével – kliens tokent kér (`X-KT-Token` fejléc;
`Authorization: Bearer …` is jó). A BKK-kulcs csak a szerveren van.

| Végpont | Mire |
|---|---|
| `GET /health` | nyilvános állapot; `features` listában jelzi a képességeket |
| `GET /auth` | token-ellenőrzés + szerveridő (`now`, ms); BKK-hívás nincs |
| `GET /api/where/<végpont>.json` | FUTÁR-proxy gyorsítótárral, backoff-fal (a `vehicles-for-location` a flotta-tárból) |
| `GET /api/gtfs-rt/<név>.pb` | GTFS-RT proxy (60 mp-es tár) |
| `GET /fleet` | a teljes Volán-flotta egy kérésben |
| `GET /history?plate=…&from=…&to=…` | szerveroldali útvonal-előzmény (ms időbélyegek, 7 nap) |
| `GET /sync/<id>[?rev=N]` | **új (v1.04)** – eszközszinkron-dokumentum; ha `rev` nem változott: `{"unchanged":true}` |
| `PUT /sync/<id>` (POST is) | **új (v1.04)** – `{"data":{"kulcs":{"v":"érték"\|null,"ts":ms}}}`; kulcsonként last-write-wins |

Eszközszinkron: külön SQLite (`$KT_DATA_DIR/sync.sqlite`). Korlátok (env-ből
állítható): dokumentum 256 KB (`KT_SYNC_MAX_BYTES`), érték 64 KB
(`KT_SYNC_MAX_VALUE`), 80 kulcs (`KT_SYNC_MAX_KEYS`), 200 dokumentum
(`KT_SYNC_MAX_DOCS`), azonosítónként legfeljebb 1 írás / mp (`KT_SYNC_MIN_GAP`,
429). Az azonosító 16–64 karakter `[A-Za-z0-9_-]`; a naplóba `/sync/[id]`
kerül, a token és az azonosító nem. A jövőbeli időbélyeget a szerver levágja.
A sync- és auth-végpontok BKK-hívást nem indítanak.
