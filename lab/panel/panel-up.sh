#!/usr/bin/env bash
# lab/panel/panel-up.sh — bring up the CSF test lab's local panel (the
# standalone `defensia-lab` docker compose project on host port 5565, from
# plan 14-02) and seed it via `lab:bootstrap`. Idempotent: safe to run on an
# already-running panel. Writes lab/.state/panel.json.
#
# Never touches the developer's dev stack (docker-compose.yml) or any
# production panel, URL or token.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"

[ -f "$PANEL_DIR/docker-compose.lab.yml" ] || die "panel repo not found at $PANEL_DIR (set DEFENSIA_PANEL_DIR)"

log "panel: starting db ($PANEL_DIR/docker-compose.lab.yml)"
panel_compose up -d --build --wait db

log "panel: starting app"
panel_compose up -d --build app

log "panel: running migrations"
panel_compose exec -T app php artisan migrate --force

log "panel: waiting for $PANEL_URL_HOST/up"
waited=0
until curl -fsS -o /dev/null "$PANEL_URL_HOST/up" 2>/dev/null; do
  [ "$waited" -lt 120 ] || die "panel: $PANEL_URL_HOST/up did not return 200 within 120s"
  sleep 2
  waited=$((waited + 2))
done

mkdir -p "$STATE_DIR"
panel_bootstrap >/dev/null

mail_default="$(json_get "$STATE_DIR/panel.json" mail_default)"
latest_agent_version="$(json_get "$STATE_DIR/panel.json" latest_agent_version)"
db_database="$(json_get "$STATE_DIR/panel.json" db_database)"
api_token="$(json_get "$STATE_DIR/panel.json" api_token)"

[ -n "$api_token" ] || die "panel: lab:bootstrap returned no api_token"
[ "$mail_default" = "log" ] || die "panel: mail_default = '$mail_default' (expected log) - refusing to treat this as a safe lab panel"
[ -z "$latest_agent_version" ] || die "panel: latest_agent_version = '$latest_agent_version' (expected empty) - refusing to treat this as a safe lab panel"
[ "$db_database" = "defensia_lab" ] || die "panel: db_database = '$db_database' (expected defensia_lab) - refusing to treat this as a safe lab panel"

log "panel: up and bootstrapped (mail_default=$mail_default db_database=$db_database latest_agent_version=<empty>)"
