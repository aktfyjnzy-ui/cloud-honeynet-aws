# scripts/ — Pipeline de Threat Intelligence y Notificaciones

Este directorio contiene los scripts operacionales del proyecto
Cloud HoneyNet AWS. Se organizan en dos subsistemas independientes:
el pipeline de Threat Intelligence y el sistema de notificaciones.

---

## Estructura

scripts/  
├── telegram/  
│ └── send_telegram.sh Envío de notificaciones vía Telegram Bot API  
└── ti/  
├── tienrichment.py Enriquecimiento de IPs con APIs externas  
├── ti_dryrun_archives.py Extracción de IPs desde Wazuh archives  
├── gen_cdb_from_candidates.py Generación de CDB desde candidates JSONL  
├── ti_emit_matches.py Emisión de matches TI al socket de analysisd  
├── run_ti_pipeline.sh Orquestador — pipeline baseline (sin APIs)  
└── run_ti_enrichment_v1.sh Orquestador — pipeline de enriquecimiento


---

## Dependencias del sistema

```bash
# Python 3.10+ (incluido en Ubuntu 22.04)
python3 --version

# Biblioteca requests (para tienrichment.py)
pip3 install requests

# curl (para send_telegram.sh — incluido en Ubuntu)
curl --version
```

## Configuración previa — Secretos

Los scripts leen credenciales desde archivos de entorno con permisos  
restrictivos. **Nunca deben subirse al repositorio.**

## `~/.honeynet_ti.env` — APIs de Threat Intelligence

```bash
ABUSEIPDB_API_KEY=<tu_clave_abuseipdb>
GREYNOISE_API_KEY=<tu_clave_greynoise_community>
OTX_API_KEY=<tu_clave_otx>
```

```bash
touch ~/.honeynet_ti.env && chmod 600 ~/.honeynet_ti.env
```

## `secrets/telegram.env` — Bot de Telegram

```bash
BOT_TOKEN=<token_del_bot>
CHAT_ID=<id_del_chat_o_canal>
```

```bash
mkdir -p secrets && chmod 700 secrets
touch secrets/telegram.env && chmod 600 secrets/telegram.env
```

## Pipeline Baseline — sin APIs

Extrae IPs directamente de los archives de Wazuh y genera una CDB  
basada en **frecuencia de aparición**. No requiere claves externas.
```text
ti_dryrun_archives.py  →  ti_candidates_YYYYMMDD.jsonl
                       →  gen_cdb_from_candidates.py
                       →  lists/cdb/honeynet-ti-ip.top200.list
```

## Ejecución manual

```bash
# Desde el directorio raíz del proyecto en el Manager
cd /home/ubuntu
bash scripts/ti/run_ti_pipeline.sh
```

## Verificar resultados
```bash
# Candidatos generados
ls -lh outputs/ti/latest/ti_candidates_*.jsonl
wc -l outputs/ti/latest/ti_candidates_*.jsonl

# CDB generada
wc -l lists/cdb/honeynet-ti-ip.top200.list
head -5 lists/cdb/honeynet-ti-ip.top200.list

# Log de ejecución
tail -30 /var/log/honeynet-ti/ti_pipeline.log
```

---

## Pipeline de Enriquecimiento — con APIs

Toma los candidatos del pipeline baseline y los enriquece consultando  
AbuseIPDB, GreyNoise y OTX. Asigna niveles de confianza `high/medium/low`.

```text
ti_candidates_YYYYMMDD.jsonl  →  tienrichment.py
                              →  ti_enriched_latest.jsonl
                              →  lists/cdb/honeynet-ti-ip.enriched.top200.list
```

## Ejecución manual

```bash
cd /home/ubuntu
bash scripts/ti/run_ti_enrichment_v1.sh
```

## Verificar resultados

```bash
# IPs enriquecidas
wc -l outputs/ti/enriched/latest/ti_enriched_latest.jsonl

# High-confidence
grep '"confidence":"high"' \
    outputs/ti/enriched/latest/ti_enriched_latest.jsonl | wc -l

# CDB enriched
wc -l lists/cdb/honeynet-ti-ip.enriched.top200.list
head -5 lists/cdb/honeynet-ti-ip.enriched.top200.list

# Log con conteo de llamadas API
grep "Enriched IPs\|AbuseIPDB calls\|GreyNoise calls" \
    /home/ubuntu/logs/tienrichment.log | tail -5
```

## Actualizar CDB en Wazuh Manager

Después de cada ejecución del pipeline de enriquecimiento, copiar  
la CDB al directorio de listas de Wazuh y recargar:

```bash
sudo cp lists/cdb/honeynet-ti-ip.enriched.top200.list \
    /var/ossec/etc/lists/honeynet-ti-ip.enriched.top200

sudo systemctl restart wazuh-manager
```

---

## Emisión directa a analysisd — `ti_emit_matches.py`

Script auxiliar que emite matches TI **directamente al socket Unix**  
de `analysisd`. Útil para forzar la generación de alertas sobre IPs  
históricas sin esperar un nuevo evento.

```bash
python3 scripts/ti/ti_emit_matches.py
```

Verifica el archivo de seen para no re-emitir IPs ya procesadas:

```bash
cat /var/log/honeynet-ti/ti_seen_high.txt | wc -l
# → Número de IPs únicas emitidas históricamente
```


---

## Notificaciones Telegram — `send_telegram.sh`

Envía un mensaje al canal de Telegram configurado en `secrets/telegram.env`.

## Prueba manual

```bash
bash scripts/telegram/send_telegram.sh "HoneyNet: prueba OK"
# → OK: Mensaje enviado
```

## Integración con los pipelines

Ambos orquestadores llaman a `send_telegram.sh` automáticamente al  
finalizar, enviando un resumen truncado a ≤3500 caracteres (límite  
práctico de la API de Telegram).

---

## Logs

|Archivo|Generado por|
|---|---|
|`/var/log/honeynet-ti/ti_pipeline.log`|`run_ti_pipeline.sh`|
|`/var/log/honeynet-ti/ti_enrichment_v1.log`|`run_ti_enrichment_v1.sh`|
|`/home/ubuntu/logs/tienrichment.log`|`tienrichment.py`|
|`/var/log/honeynet-ti/ti_matches.jsonl`|`ti_emit_matches.py`|
|`/var/log/honeynet-ti/ti_seen_high.txt`|`ti_emit_matches.py`|

---

## Directorios generados en runtime

Estos directorios son generados automáticamente por los scripts  
y **no se subieron al repositorio**:

```text
~/inputs/                     Archives 48h consolidados
~/outputs/ti/runs/            Snapshots de cada ejecución (rotación 7 días)
~/outputs/ti/latest/          Último run del baseline
~/outputs/ti/enriched/        Salidas del enriquecimiento
~/lists/cdb/                  CDB generadas (antes de copiar a Wazuh)
~/scripts/ti/cache/           Cache JSON de TI (24h TTL)
```

## Automatización — Cron

Ver configuración completa en  
[`docs/02-wazuh-integracion/threat-intelligence.md`](cloud-honeynet-aws/docs/02-wazuh-integracion/threat-intelligence)

```bash
# Verificar cron activo
sudo crontab -l -u root | grep ti
```
## Referencias

- [Documentación TI completa](cloud-honeynet-aws/docs/02-wazuh-integracion/threat-intelligence)
    
- [Reglas Wazuh que consumen la CDB](cloud-honeynet-aws/docs/02-wazuh-integracion/reglas-custom)
    
- [AbuseIPDB API v2](https://docs.abuseipdb.com/)
    
- [GreyNoise Community API](https://docs.greynoise.io/)
    
- [AlienVault OTX](https://otx.alienvault.com/)