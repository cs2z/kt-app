#!/usr/bin/env bash
# GitHub-ról frissíti a /opt/kt-app szerverét. systemd timer hívja 10 percenként.
# Napló: journalctl -u kt-update
set -euo pipefail

REPO="${KT_REPO_DIR:-/opt/kt-app}"
UNIT_SRC="$REPO/server/systemd"
VENV="${KT_VENV_DIR:-/var/lib/kt-server/venv}"

if [[ ! -d "$REPO/.git" ]]; then
  echo "nincs git tár: $REPO" >&2
  exit 1
fi

cd "$REPO"
before="$(git log -1 --pretty=%H -- server 2>/dev/null || git rev-parse HEAD)"

git fetch --quiet origin
# követett ág, vagy az origin alapértelmezett ága
if branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" && [[ -n "$branch" && "$branch" != "HEAD" ]]; then
  git pull --ff-only --quiet origin "$branch"
else
  def="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
  def="${def#origin/}"
  def="${def:-main}"
  git checkout -q --force "$def"
  git pull --ff-only --quiet origin "$def"
fi

after="$(git log -1 --pretty=%H -- server 2>/dev/null || git rev-parse HEAD)"

# a sbin-másolatok és unit fájlok legyenek naprakészek
if [[ -x "$REPO/server/kt-update.sh" ]]; then
  install -m 0755 "$REPO/server/kt-update.sh" /usr/local/sbin/kt-update
fi
if [[ -x "$REPO/server/kt-set-domain" ]]; then
  install -m 0755 "$REPO/server/kt-set-domain" /usr/local/sbin/kt-set-domain
fi

unit_changed=0
if [[ -d "$UNIT_SRC" ]]; then
  for u in kt-server.service kt-update.service kt-update.timer; do
    if [[ -f "$UNIT_SRC/$u" ]] && ! cmp -s "$UNIT_SRC/$u" "/etc/systemd/system/$u" 2>/dev/null; then
      install -m 0644 "$UNIT_SRC/$u" "/etc/systemd/system/$u"
      unit_changed=1
    fi
  done
  if [[ "$unit_changed" -eq 1 ]]; then
    systemctl daemon-reload
  fi
fi

if [[ -f "$REPO/server/requirements.txt" && -x "$VENV/bin/pip" ]]; then
  # csak akkor telepít, ha van nem-komment sor
  if grep -qE '^[^#[:space:]]' "$REPO/server/requirements.txt"; then
    "$VENV/bin/pip" install -q -r "$REPO/server/requirements.txt"
  fi
fi

if [[ "$before" != "$after" || "$unit_changed" -eq 1 ]]; then
  echo "server/ frissült ${before} -> ${after} (unit_changed=${unit_changed}), kt-server újraindul"
  systemctl restart kt-server
else
  echo "server/ változatlan (${after})"
fi
