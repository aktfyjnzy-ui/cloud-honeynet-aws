#!/usr/bin/env bash
set -euo pipefail
umask 027

BASE_DIR="/home/ubuntu"
LOG_FILE="/var/log/honeynet-ti/ti_enrichment_v1.log"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

ENRICH_LATEST="${BASE_DIR}/outputs/ti/enriched/latest/ti_enriched_latest.jsonl"
SEND_TG="${BASE_DIR}/scripts/telegram/send_telegram.sh"

mkdir -p "$(dirname "${LOG_FILE}")"

{
  echo "=== TI ENRICHMENT v1 START ${TS} ==="
  date -u
} >> "${LOG_FILE}"
exec >> "${LOG_FILE}" 2>&1

test -x "${SEND_TG}"

# 1) Ejecuta enrichment v1
/usr/bin/python3 "${BASE_DIR}/scripts/ti/tienrichment.py"

# 2) Resumen para Telegram (sin secrets)
if [[ ! -f "${ENRICH_LATEST}" ]]; then
  echo "WARN: ${ENRICH_LATEST} no existe; skipping Telegram"
  exit 0
fi

# 2) Resumen para Telegram (Top 5 High por honeypot)
SUMMARY="$(
  /usr/bin/python3 - <<'PY'
import json
from collections import defaultdict
path = "/home/ubuntu/outputs/ti/enriched/latest/ti_enriched_latest.jsonl"
by_source = defaultdict(list)
total = high = 0
with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        total += 1
        r = json.loads(line)
        ip = r.get("ip")
        src = r.get("@source") or r.get("source") or "unknown"
        conf = r.get("confidence")
        ti = r.get("ti") or {}
        abuse = ti.get("abuseipdb") or {}
        otx = ti.get("otx") or {}
        score = abuse.get("score")
        if not isinstance(score, int): score = -1
        pulses = otx.get("pulse_count")
        if not isinstance(pulses, int): pulses = 0
        if conf == "high":
            high += 1
            by_source[src].append((score, ip, pulses))
for src in by_source:
    by_source[src].sort(reverse=True, key=lambda x: x[0])
lines = []
lines.append(f"Input: {path}")
lines.append(f"Total IPs enriquecidas: {total}")
lines.append(f"High-confidence: {high}")
lines.append("")
for src in sorted(by_source.keys()):
    lines.append(f"[{src.upper()}] Top 5 High (por AbuseIPDB score):")
    for i, (score, ip, pulses) in enumerate(by_source[src][:5], 1):
        lines.append(f"{i}. {ip} score={score} otx_pulses={pulses}")
    lines.append("")
print("\n".join(lines))
PY
)"

# 3) Truncar por límite práctico de Telegram
MSG="$(printf "%s" "${SUMMARY}" | head -c 3500)"

"${SEND_TG}" "Reporte TI enriquecido (v1) ${TS}\\n${MSG}" || echo "WARN: Telegram send failed"

echo "=== TI ENRICHMENT v1 END ${TS} ==="
