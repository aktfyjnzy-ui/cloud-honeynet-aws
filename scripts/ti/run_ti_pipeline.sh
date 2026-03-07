#!/usr/bin/env bash
set -euo pipefail
umask 027

BASE_DIR="/home/ubuntu"
ARCH_BASE="/var/ossec/logs/archives"
LOG_FILE="/var/log/honeynet-ti/ti_pipeline.log"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${BASE_DIR}/outputs/ti/runs/${TS}"
LATEST_DIR="${BASE_DIR}/outputs/ti/latest"

mkdir -p "${RUN_DIR}"

# Log centralizado (stdout+stderr) con timestamp de ejecución
{
  echo "=== TI PIPELINE START ${TS} ==="
  date -u
} >> "${LOG_FILE}"

exec >> "${LOG_FILE}" 2>&1

# 0) Verificación rápida de scripts esperados
test -f "${BASE_DIR}/scripts/ti/ti_dryrun_archives.py"
test -f "${BASE_DIR}/scripts/ti/gen_cdb_from_candidates.py"
test -x "${BASE_DIR}/scripts/telegram/send_telegram.sh"

# 1) Construye input 48h (hoy + ayer) desde archives
YEAR_TODAY="$(date -u +%Y)"
MON_TODAY="$(date -u +%b)"
DAY_TODAY="$(date -u +%d)"

YEAR_YEST="$(date -u -d '1 day ago' +%Y)"
MON_YEST="$(date -u -d '1 day ago' +%b)"
DAY_YEST="$(date -u -d '1 day ago' +%d)"

F_TODAY="${ARCH_BASE}/${YEAR_TODAY}/${MON_TODAY}/ossec-archive-${DAY_TODAY}.json"
F_TODAY_GZ="${F_TODAY}.gz"

F_YEST="${ARCH_BASE}/${YEAR_YEST}/${MON_YEST}/ossec-archive-${DAY_YEST}.json"
F_YEST_GZ="${F_YEST}.gz"

INPUT_STABLE="${BASE_DIR}/inputs/wazuh_archives_48h.jsonl"
INPUT_TS="${BASE_DIR}/inputs/wazuh_archives_48h_${TS}.jsonl"
TMP_INPUT="$(mktemp)"
trap 'rm -f "${TMP_INPUT}"' EXIT

echo "[+] Building 48h input: ${INPUT_STABLE}"

# Ayer (con fallback a anteayer si el archivo está vacío/corrupto/ausente)
YEST_OK=false

# Intento 1: .gz de ayer no vacío y válido
if [[ -f "${F_YEST_GZ}" ]] && [[ -s "${F_YEST_GZ}" ]]; then
  if sudo gzip -t "${F_YEST_GZ}" 2>/dev/null; then
    sudo zcat "${F_YEST_GZ}" > "${TMP_INPUT}"
    YEST_OK=true
  fi
fi

# Intento 2: .json de ayer no vacío
if [[ "${YEST_OK}" == false ]] && [[ -f "${F_YEST}" ]] && [[ -s "${F_YEST}" ]]; then
  echo "WARN: Usando .json descomprimido de ayer (${F_YEST})"
  sudo cat "${F_YEST}" > "${TMP_INPUT}"
  YEST_OK=true
fi

# Intento 3: fallback a anteayer (si ayer está vacío/corrupto/ausente por ENOSPC)
if [[ "${YEST_OK}" == false ]]; then
  F_2D_GZ="${ARCH_BASE}/$(date -u -d '2 days ago' +%Y/%b)/ossec-archive-$(date -u -d '2 days ago' +%d).json.gz"
  F_2D="${F_2D_GZ%.gz}"
  echo "WARN: Archivo de ayer ausente/vacío/corrupto; fallback a 2 días atrás: ${F_2D_GZ}"
  if [[ -f "${F_2D_GZ}" ]] && [[ -s "${F_2D_GZ}" ]] && sudo gzip -t "${F_2D_GZ}" 2>/dev/null; then
    sudo zcat "${F_2D_GZ}" > "${TMP_INPUT}"
    YEST_OK=true
  elif [[ -f "${F_2D}" ]] && [[ -s "${F_2D}" ]]; then
    sudo cat "${F_2D}" > "${TMP_INPUT}"
    YEST_OK=true
  fi
fi

if [[ "${YEST_OK}" == false ]]; then
  echo "ERROR: No hay archivo de archivo usable para ayer ni anteayer" >&2
  exit 2
fi

# Hoy
if [[ -f "${F_TODAY}" ]]; then
  sudo cat "${F_TODAY}" >> "${TMP_INPUT}"
elif [[ -f "${F_TODAY_GZ}" ]]; then
  if sudo gzip -t "${F_TODAY_GZ}"; then
    sudo zcat "${F_TODAY_GZ}" >> "${TMP_INPUT}"
  else
    echo "ERROR: Today archive gzip corrupt (${F_TODAY_GZ})" >&2
    exit 2
  fi
else
  echo "ERROR: Missing today archive (${F_TODAY} or ${F_TODAY_GZ})" >&2
  exit 2
fi

mkdir -p "${BASE_DIR}/inputs"
install -m 0640 "${TMP_INPUT}" "${INPUT_STABLE}"
install -m 0640 "${TMP_INPUT}" "${INPUT_TS}"

# 2) Ejecuta TI dry-run (argumentos requeridos por el script)
echo "[+] Running ti_dryrun_archives.py --input ${INPUT_STABLE} --outdir ${RUN_DIR}"
python3 "${BASE_DIR}/scripts/ti/ti_dryrun_archives.py" \
  --input "${INPUT_STABLE}" \
  --outdir "${RUN_DIR}"

CAND_FILE="$(ls -1 "${RUN_DIR}"/ti_candidates_*.jsonl 2>/dev/null | tail -1 || true)"
TOP_FILE="$(ls -1 "${RUN_DIR}"/ti_top_*.txt 2>/dev/null | tail -1 || true)"

if [[ -z "${CAND_FILE}" ]]; then
  echo "ERROR: ti_candidates_*.jsonl not generated in ${RUN_DIR}" >&2
  exit 3
fi

# 3) Regenera CDB (FULL + TOP200)
FULL_LIST="${BASE_DIR}/lists/cdb/honeynet-ti-ip.list"
TOP_LIST="${BASE_DIR}/lists/cdb/honeynet-ti-ip.top200.list"

echo "[+] Generating CDB lists from: ${CAND_FILE}"
python3 "${BASE_DIR}/scripts/ti/gen_cdb_from_candidates.py" \
  --input "${CAND_FILE}" \
  --output "${FULL_LIST}" \
  --top-output "${TOP_LIST}" \
  --min-count 2 \
  --max-keys 200

# Copia listas al RUN_DIR (evidencia)
[[ -f "${BASE_DIR}/lists/cdb/honeynet-ti-ip.list" ]] && cp -a "${BASE_DIR}/lists/cdb/honeynet-ti-ip.list" "${RUN_DIR}/"
[[ -f "${BASE_DIR}/lists/cdb/honeynet-ti-ip.top200.list" ]] && cp -a "${BASE_DIR}/lists/cdb/honeynet-ti-ip.top200.list" "${RUN_DIR}/"

# 4) Actualiza "latest"
rm -rf "${LATEST_DIR}"
mkdir -p "${LATEST_DIR}"
cp -a "${RUN_DIR}/." "${LATEST_DIR}/"

# 5) Telegram: límite práctico 4096 chars por mensaje; truncamos a 3500 para margen [web:18][web:20]
echo "[+] Telegram notification (truncated summary)"
if [[ -n "${TOP_FILE}" ]]; then
  MSG="$(sed -n '1,60p' "${TOP_FILE}" | head -c 3500)"
  "${BASE_DIR}/scripts/telegram/send_telegram.sh" "Reporte TI automático (baseline v0) ${TS}\n${MSG}" || echo "WARN: Telegram send failed"
else
  echo "WARN: TOP file not found in run dir; skipping Telegram"
fi

# 6) Rotación 7 días
echo "[+] Rotation (7 days)"
find "${BASE_DIR}/outputs/ti/runs" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
find "${BASE_DIR}/inputs" -type f -name "wazuh_archives_48h_*.jsonl" -mtime +7 -delete 2>/dev/null || true

# 6.1) Rotación por cantidad de snapshots inputs (mantener últimos 6)
cd "${BASE_DIR}/inputs" || true
ls -1t wazuh_archives_48h_*.jsonl 2>/dev/null | tail -n +7 | xargs -r rm -f
cd - >/dev/null || true

# === FIX PERMISOS PERMANENTE (evita root:root) ===
echo "[+] Aplicando fix de permisos automático..."
chown -R ubuntu:ubuntu /home/ubuntu/inputs /home/ubuntu/outputs /home/ubuntu/lists 2>/dev/null || true
find /home/ubuntu/inputs /home/ubuntu/outputs/ti -type d -exec chmod 755 {} + 2>/dev/null || true
find /home/ubuntu/inputs /home/ubuntu/outputs/ti -type f -exec chmod 644 {} + 2>/dev/null || true

echo "=== TI PIPELINE END ${TS} ==="
