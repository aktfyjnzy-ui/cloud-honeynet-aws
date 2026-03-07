# Despliegue del Stack Wazuh — SIEM Central

> **Instancia:** `i-068d997b895a0ed8c` · m7i-flex.large · Ubuntu 22.04 LTS  
> **IP privada:** `10.0.20.51`  
> **Versión:** Wazuh Manager + Indexer + Dashboard 4.14.2  
> **Fecha de despliegue:** 2026-02-04  
> **Estado al cierre del proyecto:** Operativo (30 días continuos)

---

## Tabla de Contenidos

1. [Descripción](#1-descripción)
2. [Pre-requisitos](#2-pre-requisitos)
3. [Instalación All-in-One](#3-instalación-all-in-one)
4. [Post-instalación](#4-post-instalación)
5. [Habilitación de Archives](#5-habilitación-de-archives)
6. [Index Patterns en Dashboard](#6-index-patterns-en-dashboard)
7. [Gestión de Agentes](#7-gestión-de-agentes)
8. [Acceso Administrativo](#8-acceso-administrativo)
9. [Validación del Stack Completo](#9-validación-del-stack-completo)
10. [Troubleshooting](#10-troubleshooting)
11. [Capturas de Evidencia](#11-capturas-de-evidencia)

---

## 1. Descripción

El stack Wazuh funciona como el **cerebro central** de la HoneyNet. Concentra
todos los eventos de los tres sensores, aplica reglas de correlación,
enriquece con Threat Intelligence y expone los resultados en un dashboard
en tiempo real.

Los tres componentes se instalan en una sola instancia (**all-in-one**):

| Componente | Función |
|:-----------|:--------|
| **Wazuh Manager** | Recibe eventos de agentes, aplica decoders y reglas, genera alertas |
| **Wazuh Indexer** | Almacenamiento basado en OpenSearch; indexa todos los eventos y alertas |
| **Wazuh Dashboard** | Interfaz Kibana-based para visualización, Discover y Threat Hunting |

---

## 2. Pre-requisitos

### 2.1 Security Group (`chn-sg-wazuh`)

| Dirección | Protocolo | Puerto(s) | Origen |
|:----------|:----------|:----------|:-------|
| Inbound | TCP | 1514 | `chn-sg-cowrie`, `chn-sg-tpot`, `chn-sg-dionaea` |
| Inbound | TCP | 1515 | `chn-sg-cowrie`, `chn-sg-tpot`, `chn-sg-dionaea` |
| Inbound | TCP | 443 | `<IP-admin>/32` |
| Inbound | TCP | 22 | `<IP-admin>/32` |
| Outbound | TCP | Efímeros | `0.0.0.0/0` |

> Los puertos 1514 y 1515 deben tener como origen **los Security Groups
> de los sensores** (no CIDRs), para que solo las instancias EC2 de la
> HoneyNet puedan conectarse como agentes.

### 2.2 Network ACL (`chn-nacl-wazuh`)

Verificar que la NACL de la subnet Wazuh tenga las reglas en el orden correcto:

| Regla | Dirección | Puerto(s) | Origen | Acción |
|:------|:----------|:----------|:-------|:-------|
| 100 | Inbound | 1514, 1515 | `10.0.10.0/24` | ALLOW |
| 200 | Inbound | 443 | `<IP-admin>/32` | ALLOW |
| * | Inbound | ALL | ALL | DENY |
| 100 | Outbound | 1024–65535 | `10.0.10.0/24` | ALLOW |
| * | Outbound | ALL | ALL | DENY |

> **Orden crítico:** Las reglas ALLOW de los puertos de Wazuh deben
> tener número de regla **menor** que cualquier DENY genérico en la misma
> dirección. Las NACLs se evalúan en orden ascendente por número de regla.

### 2.3 Requisitos de Hardware

| Recurso | Mínimo recomendado | Instancia usada |
|:--------|:-------------------|:----------------|
| RAM | 8 GB | m7i-flex.large |
| CPU | 4 vCPU | m7i-flex.large |
| Disco | 50 GB+ | EBS gp3 |

---

## 3. Instalación All-in-One

### 3.1 Descargar el instalador

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
```

## 3.2 Configurar `config.yml`

Editar `config.yml` con la configuración mínima para un nodo all-in-one:

```text
nodes:
  indexer:
    - name: node-1
      ip: "10.0.20.51"

  server:
    - name: wazuh-1
      ip: "10.0.20.51"

  dashboard:
    - name: dashboard
      ip: "10.0.20.51"
```

## 3.3 Ejecutar la instalación

```bash
sudo bash wazuh-install.sh -a
```

El script instala y configura automáticamente los tres componentes.  
Al finalizar, imprime las credenciales de acceso al Dashboard:

```text
INFO: --- Summary ---
INFO: You can access the web interface https://<ip_pública_ec2_wazuh>:443
    User: admin
    Password: <PASSWORD-GENERADO>
```

> **Guardar estas credenciales de inmediato.** Son generadas una  
> sola vez durante la instalación.

## 3.4 Verificar estado de los servicios

```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
```

Los tres servicios deben estar en estado `active (running)`.

## 4. Post-instalación

## 4.1 Verificar versiones instaladas

```bash
sudo /var/ossec/bin/wazuh-control info
# Wazuh Manager v4.14.2

apt-cache policy wazuh-indexer wazuh-dashboard
# Installed: 4.14.2-1
```

## 4.2 Deshabilitar repositorio APT

Prevenir upgrades accidentales que puedan romper el stack durante la operación:

```bash
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

## 4.3 Acceso inicial al Dashboard
```text
URL:      https://<IP-publica-wazuh>:443
Usuario:  admin
Password: <PASSWORD-GENERADO-EN-INSTALACIÓN>
```

## 5. Habilitación de Archives

Por defecto, Wazuh solo indexa eventos que generan una alerta activa  
(`wazuh-alerts-*`). Para capturar **todos** los eventos de los honeypots  
(incluyendo los que no disparan reglas) se debe habilitar el archiving.

## 5.1 Habilitar `logall_json` en el Manager

Editar `/var/ossec/etc/ossec.conf` en el Manager:

```xml
<ossec_config>
  <global>
    <logall>no</logall>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

> `logall=no` mantiene el archivo de texto plano deshabilitado.  
> `logall_json=yes` habilita `archives.json`, que es la fuente para el  
> índice OpenSearch de archives.

## 5.2 Habilitar el módulo archives en Filebeat

```bash
sudo sed -i \
    's/archives.enabled: false/archives.enabled: true/' \
    /etc/filebeat/modules.d/wazuh.yml

# Verificar el cambio
grep "archives.enabled" /etc/filebeat/modules.d/wazuh.yml
# → archives.enabled: true
```

## 5.3 Reiniciar servicios
```bash
sudo systemctl restart filebeat
sudo systemctl restart wazuh-manager
```

## 5.4 Verificar creación del índice
```bash
curl -sk -u admin:<PASSWORD> \
    https://localhost:9200/_cat/indices/wazuh-archives-* \
    | grep "wazuh-archives"
# → debe listar wazuh-archives-4.x-YYYY.MM.DD
```

## 6. Index Patterns en Dashboard

Para poder consultar los eventos en Discover, se deben crear dos  
index patterns en el Dashboard.

## 6.1 `wazuh-alerts-*` (alertas)

```text
Dashboard → Stack Management → Index Patterns → Create
Pattern:    wazuh-alerts-*
Time field: timestamp
```

## 6.2 `wazuh-archives-*` (todos los eventos)

```text
Dashboard → Stack Management → Index Patterns → Create
Pattern:    wazuh-archives-*
Time field: timestamp
```

> Una vez creados, ambos patrones aparecen en **Discover** para  
> ejecutar búsquedas y filtros como `data.@source:"cowrie"`.

---

## 7. Gestión de Agentes

## 7.1 Listar agentes registrados

```bash
sudo /var/ossec/bin/agent_control -l
```

Estado final del proyecto con los tres sensores activos:

```bash
Wazuh agent_control. List of available agents:
   ID: 000, Name: ip-10-0-20-51 (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: ip-10-0-10-36,  IP: any, Active   ← Cowrie
   ID: 002, Name: ip-10-0-10-76,  IP: any, Active   ← T-Pot CE
   ID: 003, Name: ip-10-0-10-154, IP: any, Active   ← Dionaea
```

## 7.2 Verificar conectividad agente → Manager

Desde cualquier sensor:

```bash
nc -zv -w 3 10.0.20.51 1514 && echo "OK" || echo "FAIL"
nc -zv -w 3 10.0.20.51 1515 && echo "OK" || echo "FAIL"
```

### 7.3 Reglas de correlación activas

Las reglas custom residen en `/var/ossec/etc/rules/`. Ver archivos
completos en [`configs/wazuh/`](../../configs/wazuh/):

| Archivo | Cobertura |
|:--------|:----------|
| `100-cowrie_rules.xml` | Eventos SSH/Telnet Cowrie (100500–100513) |
| `local_rules.xml` | TI enrichment · T-Pot · Dionaea · brute-force thresholds · correlación multi-honeypot |

#### Resumen de reglas en `local_rules.xml`

| Rule ID | Descripción | Nivel | MITRE |
|:--------|:------------|:------|:------|
| 100550 | TI CDB match — Cowrie (hijo de 100500) | 10 | — |
| 100578 | TI alert — Cowrie | 10 | — |
| 100568 | Parent rule — T-Pot (todos los eventos) | 0 | — |
| 100582 | Parent rule — Dionaea (todos los eventos) | 0 | — |
| 100551 | TI CDB match — T-Pot (hijo de 100568) | 10 | — |
| 100579 | TI alert — T-Pot | 10 | — |
| 100553 | TI CDB match — Dionaea (hijo de 100582) | 10 | — |
| 100580 | TI alert — Dionaea | 10 | — |
| 100571 | T-Pot: RDP connection request | 4 | T1046 |
| 100572 | T-Pot: SSH scan/session | 4 | T1046 |
| 100573 | Cowrie: brute-force SSH (≥8 en 120s) | 10 | T1110 |
| 100574 | T-Pot: alta repetición RDP (≥10 en 300s) | 8 | T1046 |
| 100575 | T-Pot: alta repetición SSH (≥10 en 300s) | 8 | T1046 |
| 100576 | Correlación multi-honeypot (≥2 honeypots/600s) | 12 | T1595 |
| 100577 | Cowrie: dropper command wget/curl/tftp | 12 | T1105 |
| 100581 | T-Pot: scan/probe NMAP/CINS/ET | 3 | T1046 |
| 100583 | Dionaea: cualquier conexión capturada | 3 | T1203 |
| 100584 | Dionaea: intento SMB TCP/445 | 6 | T1021.002 |
| 100585 | T-Pot: Suricata IDS alert con contexto MITRE | 3 | T1046 |

> **Nota sobre orden de carga:** `local_rules.xml` se carga **después**
> de `100-cowrie_rules.xml`. Las reglas TI de Cowrie (100550/100578)
> dependen de la regla padre 100500 definida en `100-cowrie_rules.xml`,
> por lo que este orden de carga es crítico para que la correlación
> funcione correctamente.

Aplicar cambios en reglas:

```bash
sudo systemctl restart wazuh-manager

# Verificar que el Manager arrancó sin errores de sintaxis XML
sudo /var/ossec/bin/wazuh-analysisd -t
# rc=0 → reglas válidas
```


***
## 8. Acceso Administrativo

El acceso a la instancia Wazuh se realiza mediante **SSH con clave .pem**
generada al momento de crear la EC2 en la consola AWS.

```powershell
ssh -o ServerAliveInterval=60 -i ssh-key.pem ubuntu@34.193.65.114
```

| Parámetro  | Valor                                           |
| ---------- | ----------------------------------------------- |
| Usuario    | `ubuntu`                                        |
| IP pública | `34.193.65.114`                                 |
| Puerto     | TCP/22 (restringido a `<IP-admin>/32` en el SG) |
| Clave      | `ssh-key.pem` (generada en EC2 Key Pairs)       |
> `ServerAliveInterval=60` evita que la sesión SSH se corte por  
> inactividad durante operaciones largas (instalaciones, reinicios  
> de servicios, etc.).

## 9. Validación del Stack Completo
```bash
# 1. Tres servicios activos
for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
    echo -n "$svc: "
    systemctl is-active $svc
done
# → active (x3)

# 2. Agentes conectados
sudo /var/ossec/bin/agent_control -l | grep Active
# → 3 agentes Active + 1 Local (server)

# 3. Archives habilitados
grep "logall_json" /var/ossec/etc/ossec.conf
# → <logall_json>yes</logall_json>

grep "archives.enabled" /etc/filebeat/modules.d/wazuh.yml
# → archives.enabled: true

# 4. Índices existentes en OpenSearch
curl -sk -u admin:<PASSWORD> \
    https://localhost:9200/_cat/indices/wazuh-* \
    | awk '{print $3, $7}' | sort
# → wazuh-alerts-4.x-*     (con documentos)
# → wazuh-archives-4.x-*   (con documentos)

# 5. Dashboard accesible
curl -sk -o /dev/null -w "%{http_code}" \
    https://localhost:443
# → 200 o 302
```

## 10. Troubleshooting
| Síntoma                                        | Causa probable                                         | Solución                                                                              |
| ---------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| Dashboard inaccesible en TCP/443               | `wazuh-dashboard` no levantó                           | `systemctl restart wazuh-dashboard` + revisar `journalctl`                            |
| Índice `wazuh-archives-*` no aparece           | `logall_json` o `archives.enabled` deshabilitados      | Verificar ambos parámetros de §5 y reiniciar `filebeat` + `wazuh-manager`             |
| Agente en estado `disconnected` tras NACL edit | Orden de reglas NACL incorrecto (DENY antes que ALLOW) | Renumerar reglas: ALLOW 1514/1515 debe tener número menor que cualquier DENY genérico |
| Manager no arranca tras editar reglas          | Error de sintaxis XML en archivo de reglas             | `sudo /var/ossec/bin/wazuh-analysisd -t` para localizar el error                      |
| No llegan eventos de un agente específico      | Agente apunta a IP pública del Manager                 | Verificar `<address>` en el agente: debe ser `10.0.20.51` (IP privada)                |
| `wazuh-indexer` con alta latencia              | EBS insuficiente o burst credits agotados              | Revisar CloudWatch → métricas de disco EBS                                            |
## 11. Capturas de Evidencia

> Ubicación en el repositorio: `screenshots/dashboard/`

| Archivo                       | Contenido                                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| `wazuh-main-dashboard.png`    | Vista general del Wazuh Dashboard: contador total de eventos, distribución por sensor y mapa de ataque |
| `wazuh-endpoints-active.png`  | Dashboard → Endpoints: los 3 agentes en estado **active** (Cowrie, T-Pot, Dionaea)                     |
| `wazuh-discover-archives.png` | Discover con index `wazuh-archives-*` y eventos de los tres sensores                                   |
| `wazuh-discover-alerts.png`   | Discover con index `wazuh-alerts-*` filtrando alertas por `rule.level >= 10`                           |
## Referencias

- [Wazuh — Quickstart installation](https://documentation.wazuh.com/current/quickstart.html)
    
- [Wazuh — ossec.conf global options](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html)
    
- [Wazuh — Filebeat module configuration](https://documentation.wazuh.com/current/user-manual/manager/wazuh-archives.html)
    
- [AWS SSM Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
    
- [OpenSearch — Index management](https://opensearch.org/docs/latest/im-plugin/)