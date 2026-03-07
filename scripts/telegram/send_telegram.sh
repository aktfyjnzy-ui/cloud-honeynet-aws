#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-$(dirname "$0")/../../secrets/telegram.env}"
[ -f "$ENV_FILE" ] || { echo "ERROR: No existe $ENV_FILE"; exit 1; }

# shellcheck disable=SC1090
source "$ENV_FILE"

: "${BOT_TOKEN:?Falta BOT_TOKEN}"
: "${CHAT_ID:?Falta CHAT_ID}"

MSG="${1:-HoneyNet: prueba Telegram OK}"
curl -sS -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
  -d "chat_id=${CHAT_ID}" \
  --data-urlencode "text=${MSG}" >/dev/null

echo "OK: Mensaje enviado"
