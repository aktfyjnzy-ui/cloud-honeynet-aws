# Evidencias de Threat Intelligence — Feeds Externos

> **Fecha de consulta:** 2026-03-06  
> **Fuentes:** AbuseIPDB API v2 · GreyNoise Community API  
> **Cobertura:** 5 IPs de alto interés documentadas durante la operación

---

## Estructura

docs/03-analisis/evidencias-ti/  
├── README.md Este archivo  
├── greynoise-3.130.168.2.json  
├── greynoise-3.129.187.38.json 
├── greynoise-18.218.118.203.json 
├── greynoise-158.51.96.38.json 
├── greynoise-201.187.98.150.json 
├── abuseipdb-summary-3.130.168.2.json 
├── abuseipdb-summary-3.129.187.38.json 
├── abuseipdb-summary-18.218.118.203.json 
├── abuseipdb-summary-158.51.96.38.json 
└── abuseipdb-summary-201.187.98.150.json 


> Los archivos `reporte-abuseipdb-*.json` completos (1.5–2.7 MB cada uno)
> se mantienen en Drive como respaldo pero **no se versionan en Git**
> por su tamaño y porque contienen reportes individuales de terceros.
> Están excluidos vía `.gitignore`:
> ```
> docs/03-analisis/evidencias-ti/reporte-abuseipdb-*.json
> ```

---

## Resumen consolidado por IP

### H1 — Campaña scan.visionheight.com

#### `3.130.168.2`

| Feed | Campo | Valor |
|:-----|:------|:------|
| **AbuseIPDB** | score | 100/100 |
| | totalReports | 3,122 |
| | numDistinctUsers | 577 |
| | ISP | Amazon Technologies Inc. |
| | hostname | `scan.visionheight.com` |
| | lastReportedAt | 2026-03-06T01:22:33Z |
| **GreyNoise** | classification | `malicious` |
| | noise | `true` |
| | last_seen | 2026-03-05 |

---

#### `3.129.187.38`

| Feed | Campo | Valor |
|:-----|:------|:------|
| **AbuseIPDB** | score | 100/100 |
| | totalReports | 3,753 |
| | numDistinctUsers | 633 |
| | ISP | Amazon Technologies Inc. |
| | hostname | `scan.visionheight.com` |
| | lastReportedAt | 2026-03-06T06:12:32Z |
| **GreyNoise** | classification | `malicious` |
| | noise | `true` |
| | last_seen | 2026-03-06 |

---

#### `18.218.118.203`

| Feed | Campo | Valor |
|:-----|:------|:------|
| **AbuseIPDB** | score | 100/100 |
| | totalReports | 3,801 |
| | numDistinctUsers | 625 |
| | ISP | Amazon Technologies Inc. |
| | hostname | `scan.visionheight.com` |
| | lastReportedAt | 2026-03-06T06:16:47Z |
| **GreyNoise** | classification | `malicious` |
| | noise | `true` |
| | last_seen | 2026-03-06 |

> Las tres IPs comparten el mismo hostname `scan.visionheight.com`,
> el mismo ISP (Amazon Technologies / AS16509), la misma región
> (us-east-2) y score 100/100 — confirmando operación coordinada
> desde la misma infraestructura.

---

### H2 — Botnet SSH NetInformatik

#### `158.51.96.38`

| Feed | Campo | Valor |
|:-----|:------|:------|
| **AbuseIPDB** | score | 100/100 |
| | totalReports | **4,307** |
| | numDistinctUsers | **924** |
| | ISP | NetInformatik Inc. |
| | domain | netinformatik.com |
| | hostname | `unknown.ip-xfer.net` |
| | lastReportedAt | 2026-03-06T05:15:42Z |
| **GreyNoise** | classification | `malicious` |
| | noise | `true` |
| | last_seen | 2026-03-06 |

> Esta IP tiene el mayor número de reportantes únicos del proyecto
> (924). Los comentarios en el reporte completo confirman SSH
> brute-force masivo a nivel global con logs de sshd de múltiples
> países (US, GB, CA, DE, NL, IN, AT, BG, CZ, FR).

---

### H3 — Host sanitario comprometido

#### `201.187.98.150`

| Feed | Campo | Valor |
|:-----|:------|:------|
| **AbuseIPDB** | score | **3/100** |
| | totalReports | 4 |
| | numDistinctUsers | 1 |
| | ISP | **HOSPITAL BASE VALDIVIA** |
| | domain | gtdcompany.com |
| | country | Chile 🇨🇱 |
| | lastReportedAt | 2026-03-03T08:23:35Z |
| **GreyNoise** | classification | `suspicious` |
| | noise | `true` |
| | last_seen | 2026-03-06 |

> El score bajo de AbuseIPDB (3/100) con solo 4 reportes de **1 único
> usuario** (honeypot `www.toce.ch`, Suiza) confirma que esta IP no es
> un actor malicioso conocido — es infraestructura legítima comprometida.
> Todos los reportes son sobre **SMB TCP/445**, consistentes con
> nuestro hallazgo de 64,095 eventos. El primer reporte data de
> **2026-01-06**, indicando que el host lleva al menos 2 meses
> con malware activo antes de nuestro período de operación.

---

## Referencias cruzadas

- [IoC estructurados](cloud-honeynet-aws/docs/03-analisis/ioc)
    
- [Análisis de hallazgos](cloud-honeynet-aws/docs/03-analisis/hallazgos)
    
- [AbuseIPDB](https://www.abuseipdb.com/)
    
- [GreyNoise Community](https://viz.greynoise.io/)

## Tres detalles que vale resaltar de los datos reales 
1. **`201.187.98.150` lleva comprometida desde al menos 2026-01-06** — el primer reporte en AbuseIPDB es de enero, dos meses antes de nuestro período. Eso refuerza el análisis de H3 considerablemente. 
2. **`3.129.187.38` tiene el mayor número de reportantes únicos de la campaña visionheight** — 633 usuarios distintos, más que las otras dos IPs. Es la más agresiva de las tres. 
3. **GreyNoise clasifica a `201.187.98.150` como `suspicious`** (no `malicious`) — consistente con que es un host legítimo comprometido, no un actor malicioso puro. Ese matiz estaba implícito en el análisis y ahora está respaldado por datos. ***