#!/usr/bin/env bash
# KT köztes szerver telepítője Ubuntu 24.04-re. Rootként, egyszer kell futtatni.
# curl -fsSL https://cs2z.github.io/kt-app/server/install.sh | bash
# Újrafuttatható (idempotens). A BKK-kulcsot soha nem írja ki.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8

REPO_URL="${KT_REPO_URL:-https://github.com/cs2z/kt-app.git}"
DEFAULT_HOST="${KT_DEFAULT_HOST:-185-208-226-186.sslip.io}"
SSH_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYgxKvgrpSRVPOESYAOLAAVkYOMDlKkcD0XlZ0z7+qy kalman-ktbp"
APP_USER="kt"

DRY=0
[[ "${KT_DRYRUN:-0}" == "1" ]] && DRY=1
PREFIX="${KT_ROOT:-}"
if [[ "$DRY" -eq 1 && -z "$PREFIX" ]]; then
  PREFIX="${TMPDIR:-/tmp}/kt-dryrun-root"
fi

# dry-run / teszt: minden útvonal a PREFIX alá kerül
p() {
  local x="$1"
  if [[ -n "$PREFIX" ]]; then
    echo "${PREFIX}${x}"
  else
    echo "$x"
  fi
}

ETC_DIR="$(p /etc/kt-server)"
DATA_DIR="$(p /var/lib/kt-server)"
LOG_DIR="$(p /var/log/kt-server)"
REPO_DIR="$(p /opt/kt-app)"
VENV_DIR="${DATA_DIR}/venv"
ENV_FILE="${ETC_DIR}/env"
TOKEN_FILE="${ETC_DIR}/client-token"
CADDY_FILE="$(p /etc/caddy/Caddyfile)"
UNIT_DIR="$(p /etc/systemd/system)"
SBIN_DIR="$(p /usr/local/sbin)"

say() { printf '%s\n' "$*"; }
warn() { printf 'figyelem: %s\n' "$*" >&2; }
die() { printf 'hiba: %s\n' "$*" >&2; exit 1; }

if [[ "$DRY" -eq 1 ]]; then
  say "[dry-run] PREFIX=${PREFIX}"
fi

need_root() {
  if [[ "$DRY" -eq 1 ]]; then
    return 0
  fi
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "rootként kell futtatni (sudo -i, vagy a parancs elé: sudo bash)"
  fi
}

run() {
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] $*"
    return 0
  fi
  "$@"
}

need_root

# ---------- csomagok ----------
install_packages() {
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] apt-get update && apt-get install python3 python3-venv git curl ca-certificates ufw unattended-upgrades caddy …"
    return 0
  fi
  apt-get update -y
  apt-get install -y --no-install-recommends \
    python3 python3-venv python3-full \
    git curl ca-certificates gnupg \
    apt-transport-https debian-keyring debian-archive-keyring \
    ufw unattended-upgrades

  if ! command -v caddy >/dev/null 2>&1; then
    say "Caddy hivatalos apt-tárolójának beállítása…"
    install -d /usr/share/keyrings
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    apt-get update -y
    apt-get install -y caddy
  fi
  command -v caddy >/dev/null 2>&1 || die "a caddy telepítése nem sikerült"
  command -v python3 >/dev/null 2>&1 || die "a python3 telepítése nem sikerült"
  command -v git >/dev/null 2>&1 || die "a git telepítése nem sikerült"
}

# ---------- felhasználó, könyvtárak ----------
setup_user_and_dirs() {
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] useradd --system $APP_USER (kihagyva)"
  else
    if ! id -u "$APP_USER" >/dev/null 2>&1; then
      useradd --system --home-dir /var/lib/kt-server --create-home --shell /usr/sbin/nologin "$APP_USER"
    fi
  fi
  install -d -m 0750 "$ETC_DIR"
  install -d -m 0750 "$DATA_DIR"
  install -d -m 0750 "$LOG_DIR"
  install -d -m 0755 "$(p /opt)"
  install -d -m 0755 "$(dirname "$CADDY_FILE")"
  install -d -m 0755 "$SBIN_DIR"
  install -d -m 0755 "$UNIT_DIR"
  if [[ "$DRY" -eq 0 ]]; then
    chown "$APP_USER:$APP_USER" "$DATA_DIR" "$LOG_DIR"
    chown "root:$APP_USER" "$ETC_DIR"
  fi
}

# ---------- SSH kulcs rootnak ----------
setup_ssh_key() {
  local sshdir auth
  sshdir="$(p /root/.ssh)"
  auth="${sshdir}/authorized_keys"
  install -d -m 0700 "$sshdir"
  touch "$auth"
  chmod 0600 "$auth"
  if ! grep -qxF "$SSH_PUBKEY" "$auth" 2>/dev/null; then
    printf '%s\n' "$SSH_PUBKEY" >> "$auth"
    say "SSH nyilvános kulcs hozzáadva: $auth"
  else
    say "SSH nyilvános kulcs már szerepel az authorized_keys-ben"
  fi
}

# ---------- git clone / pull ----------
sync_repo() {
  if [[ "$DRY" -eq 1 && -d "${KT_LOCAL_SERVER:-}" ]]; then
    # teszt: a helyi staged server/ könyvtárat másoljuk
    install -d -m 0755 "$REPO_DIR/server"
    cp -a "${KT_LOCAL_SERVER}/." "$REPO_DIR/server/"
    # egy üres .git, hogy az útvonalak stimmeljenek (update timer a valódi gépen gitet használ)
    if command -v git >/dev/null 2>&1; then
      git -C "$REPO_DIR" init -q 2>/dev/null || true
    fi
    say "[dry-run] server kód bemásolva $REPO_DIR/server alá"
    return 0
  fi
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] git clone --filter=blob:none --sparse $REPO_URL $REPO_DIR && sparse-checkout set server"
    install -d -m 0755 "$REPO_DIR/server"
    return 0
  fi
  if [[ -d "$REPO_DIR/.git" ]]; then
    say "meglévő tár frissítése: $REPO_DIR"
    git -C "$REPO_DIR" fetch --quiet origin || git -C "$REPO_DIR" fetch origin
    local branch def
    branch="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    if [[ -n "$branch" && "$branch" != "HEAD" ]]; then
      git -C "$REPO_DIR" pull --ff-only origin "$branch"
    else
      def="$(git -C "$REPO_DIR" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
      def="${def#origin/}"
      def="${def:-main}"
      git -C "$REPO_DIR" checkout -q "$def" || git -C "$REPO_DIR" checkout -q --force "$def"
      git -C "$REPO_DIR" pull --ff-only origin "$def"
    fi
  else
    if [[ -e "$REPO_DIR" && ! -d "$REPO_DIR/.git" ]]; then
      die "$REPO_DIR létezik, de nem git tár; javítsd kézzel"
    fi
    say "tár klónozása: $REPO_URL -> $REPO_DIR"
    git clone --filter=blob:none --sparse "$REPO_URL" "$REPO_DIR"
    git -C "$REPO_DIR" sparse-checkout set server
  fi
  [[ -f "$REPO_DIR/server/server.py" ]] || die "a tárban nincs server/server.py (még nincs kint a GitHubon?)"
}

install_helpers() {
  if [[ -f "$REPO_DIR/server/kt-set-domain" ]]; then
    install -m 0755 "$REPO_DIR/server/kt-set-domain" "$SBIN_DIR/kt-set-domain"
  fi
  if [[ -f "$REPO_DIR/server/kt-update.sh" ]]; then
    install -m 0755 "$REPO_DIR/server/kt-update.sh" "$SBIN_DIR/kt-update"
  fi
}

# ---------- venv ----------
setup_venv() {
  if [[ ! -x "$VENV_DIR/bin/python3" ]]; then
    say "Python venv létrehozása: $VENV_DIR"
    if [[ "$DRY" -eq 1 ]]; then
      python3 -m venv "$VENV_DIR"
    else
      rm -rf "$VENV_DIR"
      python3 -m venv "$VENV_DIR"
      chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
    fi
  fi
  [[ "$DRY" -eq 1 ]] || chown -R "$APP_USER:$APP_USER" "$VENV_DIR"
  if [[ -f "$REPO_DIR/server/requirements.txt" ]] && grep -qE '^[^#[:space:]]' "$REPO_DIR/server/requirements.txt"; then
    if [[ "$DRY" -eq 1 ]]; then
      "$VENV_DIR/bin/pip" install -q -r "$REPO_DIR/server/requirements.txt" || true
    else
      sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install -q -r "$REPO_DIR/server/requirements.txt"
    fi
  fi
}

# ---------- kulcs és token (soha nem echo) ----------
# A meglévő env-ből kiolvas egy kulcsot anélkül, hogy kiírná.
read_env_var() {
  local file="$1" key="$2"
  python3 - "$file" "$key" << 'PY'
import pathlib, sys
p, key = pathlib.Path(sys.argv[1]), sys.argv[2]
if not p.exists():
    sys.exit(0)
for line in p.read_text(encoding="utf-8").splitlines():
    s = line.strip()
    if s.startswith(key + "="):
        val = s[len(key) + 1:]
        if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
            val = val[1:-1]
        sys.stdout.write(val)
        break
PY
}

prompt_bkk_key() {
  local existing=""
  if [[ -f "$ENV_FILE" ]]; then
    existing="$(read_env_var "$ENV_FILE" "BKK_API_KEY" || true)"
  fi
  # ha a hívó már beállította a környezetben (teszt / újratelepítés)
  if [[ -n "${BKK_API_KEY:-}" ]]; then
    return 0
  fi
  if [[ -n "$existing" ]]; then
    BKK_API_KEY="$existing"
    say "A meglévő BKK-kulcs megmarad (/etc/kt-server/env)."
    return 0
  fi
  if [[ "${KT_SKIP_PROMPT:-0}" == "1" ]]; then
    die "nincs BKK API kulcs (KT_SKIP_PROMPT=1, és az env sem tartalmazza)"
  fi
  if [[ ! -e /dev/tty ]]; then
    die "nincs /dev/tty, a kulcsot nem lehet begépelni. Futtasd interaktív terminálon, vagy állítsd be a BKK_API_KEY-t."
  fi
  printf '%s\n' "Add meg a BKK API-kulcsot. A begépelés nem látszik, Enterrel zárd." > /dev/tty
  printf 'BKK API-kulcs: ' > /dev/tty
  read -r -s BKK_API_KEY < /dev/tty
  printf '\n' > /dev/tty
  if [[ -z "${BKK_API_KEY// }" ]]; then
    die "üres kulcs, a telepítés megszakadt"
  fi
}

# srv-mav1: MÁV GTFS hozzáférés (basic auth). A meglévő érték megmarad; ha nincs, rejtett bekérés (Enter = kihagyás).
# Kihagyva a szerver /health-ben "mav-gtfs": "no-credentials"-t jelez, minden más működik.
prompt_mav_creds() {
  local eu ep
  eu="$(read_env_var "$ENV_FILE" "MAV_GTFS_USER" || true)"
  ep="$(read_env_var "$ENV_FILE" "MAV_GTFS_PASSWORD" || true)"
  [[ -n "${MAV_GTFS_USER:-}" ]] || MAV_GTFS_USER="$eu"
  [[ -n "${MAV_GTFS_PASSWORD:-}" ]] || MAV_GTFS_PASSWORD="$ep"
  if [[ -n "$MAV_GTFS_USER" && -n "$MAV_GTFS_PASSWORD" ]]; then
    say "A MÁV GTFS hozzáférés megmarad (/etc/kt-server/env)."
    return 0
  fi
  if [[ "${KT_SKIP_PROMPT:-0}" == "1" || ! -e /dev/tty ]]; then
    warn "Nincs MÁV GTFS hozzáférés megadva – a vonatkereső adat nélkül marad (mav-gtfs: no-credentials)."
    MAV_GTFS_USER=""; MAV_GTFS_PASSWORD=""
    return 0
  fi
  printf '%s\n' "MÁV GTFS hozzáférés (a vonatkeresőhöz). Üres Enter = kihagyás." > /dev/tty
  printf 'MÁV GTFS felhasználó (e-mail): ' > /dev/tty
  read -r MAV_GTFS_USER < /dev/tty
  if [[ -z "${MAV_GTFS_USER// }" ]]; then
    MAV_GTFS_USER=""; MAV_GTFS_PASSWORD=""
    warn "Kihagyva – mav-gtfs: no-credentials."
    return 0
  fi
  printf 'MÁV GTFS jelszó (nem látszik): ' > /dev/tty
  read -r -s MAV_GTFS_PASSWORD < /dev/tty
  printf '\n' > /dev/tty
  if [[ -z "${MAV_GTFS_PASSWORD// }" ]]; then
    MAV_GTFS_USER=""; MAV_GTFS_PASSWORD=""
    warn "Üres jelszó – kihagyva (mav-gtfs: no-credentials)."
  fi
}

write_env_and_token() {
  local host extra token_is_new=0
  host="$(read_env_var "$ENV_FILE" "KT_HOST" || true)"
  extra="$(read_env_var "$ENV_FILE" "KT_HOST_EXTRA" || true)"
  [[ -n "$host" ]] || host="$DEFAULT_HOST"

  local old_umask
  old_umask="$(umask)"
  umask 077
  install -d -m 0750 "$ETC_DIR"
  # env írása pythonnal, a kulcsot nem echozzuk
  BKK_API_KEY="$BKK_API_KEY" MAV_GTFS_USER="${MAV_GTFS_USER:-}" MAV_GTFS_PASSWORD="${MAV_GTFS_PASSWORD:-}" KT_WRITE_HOST="$host" KT_WRITE_EXTRA="$extra" KT_WRITE_DATA="$DATA_DIR" \
  KT_WRITE_LOG="$LOG_DIR" KT_WRITE_TOKEN_FILE="$TOKEN_FILE" \
  python3 - "$ENV_FILE" << 'PY'
import os, pathlib, tempfile, sys
path = pathlib.Path(sys.argv[1])
key = os.environ["BKK_API_KEY"]
lines = [
    "# KT szerver környezet. Ne másold chatbe, ne oszd meg.",
    "BKK_API_KEY=" + key,
    "KT_BIND=127.0.0.1",
    "KT_PORT=8787",
    "KT_DATA_DIR=" + os.environ.get("KT_WRITE_DATA", "/var/lib/kt-server"),
    "KT_LOG_DIR=" + os.environ.get("KT_WRITE_LOG", "/var/log/kt-server"),
    "KT_CLIENT_TOKEN_FILE=" + os.environ.get("KT_WRITE_TOKEN_FILE", "/etc/kt-server/client-token"),
    "KT_HOST=" + os.environ.get("KT_WRITE_HOST", "185-208-226-186.sslip.io"),
    "KT_HOST_EXTRA=" + os.environ.get("KT_WRITE_EXTRA", ""),
    "KT_POLL_ACTIVE=10",
    "KT_POLL_IDLE=45",
    "KT_IDLE_AFTER=120",
    "KT_HISTORY_DAYS=7",
    "KT_TOKEN_REQUIRED=1",
]
if os.environ.get("MAV_GTFS_USER") and os.environ.get("MAV_GTFS_PASSWORD"):
    lines += ["MAV_GTFS_USER=" + os.environ["MAV_GTFS_USER"], "MAV_GTFS_PASSWORD=" + os.environ["MAV_GTFS_PASSWORD"]]
# Path-ok a valódi (nem PREFIX-elt) helyre mutassanak systemd alatt;
# dry-runban a PREFIX-elt útvonalak kellenek, ezt a hívó már beállította.
text = "\n".join(lines) + "\n"
fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.")
try:
    os.write(fd, text.encode("utf-8"))
    os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
except Exception:
    try:
        os.close(fd)
    except Exception:
        pass
    try:
        os.unlink(tmp)
    except Exception:
        pass
    raise
PY

  if [[ ! -s "$TOKEN_FILE" ]]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(32), end="")' > "$TOKEN_FILE"
    chmod 0600 "$TOKEN_FILE"
    token_is_new=1
  fi
  umask "$old_umask"
  if [[ "$DRY" -eq 0 ]]; then
    chown "root:$APP_USER" "$ETC_DIR" "$ENV_FILE" "$TOKEN_FILE"
    chmod 0750 "$ETC_DIR"
    chmod 0640 "$ENV_FILE" "$TOKEN_FILE"
  fi

  if [[ "$DRY" -eq 1 ]]; then
    if [[ "$token_is_new" -eq 1 ]]; then
      say "[dry-run] új kliens token a $TOKEN_FILE fájlba került (élesben a terminálra is kiíródna)."
    else
      say "[dry-run] a meglévő kliens token megmarad."
    fi
  elif [[ "$token_is_new" -eq 1 ]]; then
    say ""
    say "Kliens token (ez a te terminálodon jelenik meg)."
    say "NE másold chatbe, NE küldd el üzenetben, NE tedd GitHubra."
    say "----- kliens token kezdete -----"
    cat "$TOKEN_FILE"
    printf '\n'
    say "----- kliens token vége -----"
    say "Később megnézheted: sudo cat /etc/kt-server/client-token"
    say ""
  else
    say "A meglévő kliens token megmarad. Megnézés: sudo cat /etc/kt-server/client-token"
    say "(A token értékét ne másold chatbe.)"
  fi
}

# ---------- Caddy ----------
setup_caddy() {
  local host extra=""
  host="$(read_env_var "$ENV_FILE" "KT_HOST" || true)"
  extra="$(read_env_var "$ENV_FILE" "KT_HOST_EXTRA" || true)"
  [[ -n "$host" ]] || host="$DEFAULT_HOST"
  # a kt-set-domain a Caddyfile-t írja; dry-runban a PREFIX-elt útvonalakra irányítjuk
  if [[ ! -x "$SBIN_DIR/kt-set-domain" ]]; then
    die "hiányzik $SBIN_DIR/kt-set-domain"
  fi
  if [[ "$DRY" -eq 1 ]]; then
    KT_ENV_FILE="$ENV_FILE" KT_CADDY_FILE="$CADDY_FILE" KT_DRYRUN=1 \
      "$SBIN_DIR/kt-set-domain" --only "$host" ${extra:+$extra} || \
      KT_ENV_FILE="$ENV_FILE" KT_CADDY_FILE="$CADDY_FILE" KT_DRYRUN=1 \
        "$SBIN_DIR/kt-set-domain" --only "$host"
  else
    # --only az első telepítéskor: csak a sslip.io (ktbp.hu később, DNS után)
    "$SBIN_DIR/kt-set-domain" --only "$host"
    systemctl enable --now caddy
  fi
}

# ---------- systemd ----------
setup_systemd() {
  local src="$REPO_DIR/server/systemd"
  [[ -d "$src" ]] || die "hiányzik $src"
  install -m 0644 "$src/kt-server.service" "$UNIT_DIR/kt-server.service"
  install -m 0644 "$src/kt-update.service" "$UNIT_DIR/kt-update.service"
  install -m 0644 "$src/kt-update.timer" "$UNIT_DIR/kt-update.timer"
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] systemctl daemon-reload && enable --now kt-server kt-update.timer"
    return 0
  fi
  systemctl daemon-reload
  systemctl enable --now kt-server
  systemctl enable --now kt-update.timer
}

# ---------- ufw ----------
setup_ufw() {
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] ufw allow 22,80,443 && ufw --force enable"
    return 0
  fi
  ufw allow 22/tcp comment "SSH"
  ufw allow 80/tcp comment "HTTP ACME"
  ufw allow 443/tcp comment "HTTPS"
  ufw --force enable
  say "ufw: 22, 80, 443 engedélyezve"
}

# ---------- unattended-upgrades ----------
setup_unattended() {
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] unattended-upgrades bekapcsolása"
    return 0
  fi
  apt-get install -y unattended-upgrades
  cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  # biztonságos: kernel/csomagfrissítés, automatikus reboot nincs
  if [[ ! -f /etc/apt/apt.conf.d/51kt-unattended ]]; then
    cat > /etc/apt/apt.conf.d/51kt-unattended << 'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  fi
  if systemctl list-unit-files unattended-upgrades.service >/dev/null 2>&1; then
    systemctl enable --now unattended-upgrades.service || true
  fi
}

# ---------- egészség ----------
health_check() {
  local host local_ok=0 remote_ok=0 body=""
  host="$(read_env_var "$ENV_FILE" "KT_HOST" || true)"
  [[ -n "$host" ]] || host="$DEFAULT_HOST"
  if [[ "$DRY" -eq 1 ]]; then
    say "[dry-run] curl https://${host}/health  (kihagyva)"
    say ""
    say "===== telepítés (dry-run) kész ====="
    say "A szerver élesben ezen az URL-en lesz: https://${host}"
    return 0
  fi
  # helyi /health token nélkül
  for _try in 1 2 3 4 5 6 7 8 9 10; do
    if body="$(curl -sf --max-time 3 http://127.0.0.1:8787/health 2>/dev/null)"; then
      local_ok=1
      break
    fi
    sleep 1
  done
  if [[ "$local_ok" -eq 1 ]]; then
    say "helyi /health: OK  $body"
  else
    warn "a helyi http://127.0.0.1:8787/health nem válaszolt. Nézd meg: journalctl -u kt-server -n 50 --no-pager"
  fi
  # a Let's Encryptnek kell egy kis idő
  for _try in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if body="$(curl -sf --max-time 8 "https://${host}/health" 2>/dev/null)"; then
      remote_ok=1
      break
    fi
    sleep 5
  done
  say ""
  say "===== telepítés kész ====="
  say "Nyilvános cím: https://${host}"
  if [[ "$remote_ok" -eq 1 ]]; then
    say "https://${host}/health: OK  $body"
  else
    warn "a https://${host}/health most nem válaszolt (a tanúsítványhoz a 80/443-as portnak kívülről is nyitva kell lennie)."
    warn "Helyben ellenőrizheted: curl -s http://127.0.0.1:8787/health"
  fi
  say "Később, ha a ktbp.hu DNS-e kész:  sudo kt-set-domain ktbp.hu"
  say "Kliens token megnézése:          sudo cat /etc/kt-server/client-token"
  say "A tokent, a BKK-kulcsot és a jelszavakat NE küldd chatbe."
  say "Visszajelzésnek elég: az URL és a /health válasz (OK / hibaüzenet)."
}

# ---------- futtatás ----------
install_packages
setup_user_and_dirs
setup_ssh_key
sync_repo
install_helpers
setup_venv
prompt_bkk_key
prompt_mav_creds
write_env_and_token
setup_caddy
setup_systemd
setup_ufw
setup_unattended
health_check
