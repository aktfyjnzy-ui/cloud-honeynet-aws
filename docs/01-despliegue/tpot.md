# Despliegue de T-Pot CE — Honeypot Multi-Servicio

> **Instancia:** `i-070eb1a67939cdd25` · m7i-flex.large · Ubuntu 22.04 LTS  
> **IP privada:** `10.0.10.76`  
> **Versión T-Pot:** CE 24.04.1  
> **Fecha de despliegue:** 2026-02-12  
> **Estado al cierre del proyecto:** Operativo (30 días continuos)

---

## Tabla de Contenidos

1. [Descripción](#1-descripción)
2. [Pre-requisitos](#2-pre-requisitos)
3. [Instalación de T-Pot CE](#3-instalación-de-t-pot-ce)
4. [Post-instalación y Hardening](#4-post-instalación-y-hardening)
5. [Integración con Wazuh Agent](#5-integración-con-wazuh-agent)
6. [Configuración de Logcollector](#6-configuración-de-logcollector)
7. [Validación End-to-End](#7-validación-end-to-end)
8. [Troubleshooting](#8-troubleshooting)
9. [Capturas de Evidencia](#9-capturas-de-evidencia)

---

## 1. Descripción

T-Pot CE es una plataforma Docker que despliega simultáneamente **más de 20
honeypots especializados** en un único host, cubriendo una superficie de
exposición multi-protocolo amplia. Incluye herramientas de visualización
integradas (Attack Map, Kibana interno) y exportación automática de eventos.

En este proyecto, T-Pot CE opera como el sensor de mayor cobertura de
protocolos, complementando a Cowrie (SSH) y Dionaea (SMB/malware).

| Parámetro | Valor |
|:----------|:------|
| Honeypots activos | 20+ (Cowrie, Dionaea, Conpot, Honeytrap, Mailoney, Medpot…) |
| Puerto SSH admin (post-install) | TCP/64295 |
| Puerto WebUI | TCP/64297 (HTTPS) |
| Datos y logs persistentes | `~/tpotce/data/` |
| Tipo de instalación | Mini (`i`) |

### 1.1 Requisitos de Hardware

> El plan inicial contemplaba una instancia `t3.small`. Se escaló a
> **`m7i-flex.large`** durante la implementación por los requisitos reales
> del stack Docker de T-Pot.

| Recurso | Mínimo T-Pot | Instancia usada |
|:--------|:------------|:----------------|
| RAM | 8 GB | 7.6 GiB (m7i-flex.large) |
| Disco | 128 GB | 128 GB (nvme0n1) |
| CPU | 4 vCPU | m7i-flex.large |

---

## 2. Pre-requisitos

### 2.1 Security Group (`chn-sg-tpot`)

| Dirección | Protocolo | Puerto(s) | Origen |
|:----------|:----------|:----------|:-------|
| Inbound | TCP + UDP | 1–64000 | `0.0.0.0/0` |
| Inbound | TCP | 64295 | `<IP-admin>/32` |
| Inbound | TCP | 64297 | `<IP-admin>/32` |
| Outbound | TCP | 1514, 1515 | `chn-sg-wazuh` |

> Durante la instalación abrir temporalmente **Outbound TCP/80 y
> TCP/443** para que el script descargue imágenes Docker. Cerrar al finalizar.

> T-Pot reasigna el SSH del sistema operativo al puerto **64295**
> durante la instalación. Antes de ejecutar `install.sh`, habilitar
> TCP/22 temporal desde `<IP-admin>/32` para no perder acceso.
> Una vez completada la instalación y validado el acceso por 64295,
> eliminar la regla de TCP/22.

### 2.2 Verificar sizing antes de instalar

```bash
df -hT /
# Esperado: >= 120G disponibles

free -h
# Esperado: >= 7G RAM

lsblk
# Verificar que el disco sea el esperado (nvme0n1 128G)
```
## 2.3 Conectividad con Wazuh Manager

```bash
nc -zv -w 3 10.0.20.51 1514
nc -zv -w 3 10.0.20.51 1515
# Ambos deben retornar: succeeded!
```
## 3. Instalación de T-Pot CE

## 3.1 Descargar y ejecutar el script oficial
```bash
# Como usuario no-root (ubuntu)
git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh
```

Durante la instalación, el script solicita:

|Paso|Selección|
|---|---|
|Tipo de instalación|**`i` (Mini)**|
|WEB_USER|Definir usuario para la WebUI|
|WEB_PASSWORD|Definir contraseña para la WebUI|

> El script realiza reboot automático al finalizar. El proceso completo  
> tarda entre 10 y 20 minutos dependiendo de la velocidad de descarga  
> de imágenes Docker.

## 3.2 Reconectar tras el reboot

Después del reboot, el SSH estará en el nuevo puerto:

```bash
ssh -p 64295 ubuntu@<IP-publica-tpot>
```

Si la conexión falla en 64295, verificar que el SG tenga el puerto abierto **antes** de eliminar la regla temporal de TCP/22.
## 3.3 Verificar que T-Pot está operativo

```bash
sudo systemctl status tpot --no-pager

# Verificar contenedores Docker activos
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Verificar puertos publicados
sudo ss -lntp | grep -E ':80|:22|:445|:2222'
```

Acceder a la WebUI para confirmar el despliegue visual:
```text
https://<IP-publica-tpot>:64297
```
## 3.4 Verificar persistencia de logs

```bash
ls ~/tpotce/data/
# Debe listar: cowrie/ dionaea/ suricata/ conpot/ honeytrap/ p0f/ ...

# Confirmar que los logs se están escribiendo
tail -f ~/tpotce/data/suricata/log/eve.json
```
## 4. Post-instalación y Hardening

## 4.1 Cerrar ventana temporal de egress

Una vez completada la instalación, restaurar el SG a egress mínimo:
```text
Outbound TCP/1514 → chn-sg-wazuh   (mantener)
Outbound TCP/1515 → chn-sg-wazuh   (mantener)
Outbound TCP/80   → 0.0.0.0/0      (eliminar)
Outbound TCP/443  → 0.0.0.0/0      (eliminar)
Inbound  TCP/22   → <IP-admin>/32  (eliminar, ya no necesario)
```

Verificar que el SG queda solo con los puertos definidos en **2.1**
## 5. Integración con Wazuh Agent

## 5.1 Instalación del agente

> T-Pot CE no incluye el repositorio APT de Wazuh. Debe agregarse manualmente.

```bash
# Abrir ventana temporal egress TCP/80,443 en el SG

# Importar GPG key — aplicar sudo a ambos lados del pipe
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

# Agregar repositorio
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
    https://packages.wazuh.com/4.x/apt/ stable main" | \
    sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo WAZUH_MANAGER="10.0.20.51" apt install -y wazuh-agent

# Deshabilitar repo para evitar upgrades accidentales
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

>**Error frecuente:** `gpg: failed to create temporary file — Permission denied`. Causa: ejecutar `gpg` sin `sudo` en el lado derecho del pipe.  
>Solución: aplicar `sudo` explícitamente a `gpg`, no solo a `curl`.

## 5.2 Configurar el agente

Editar `/var/ossec/etc/ossec.conf` y verificar que `<address>` apunta  
a la **IP privada** del Manager:
```xml
<ossec_config>
  <client>
    <server>
      <address>10.0.20.51</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>10.0.20.51</manager_address>
      <port>1515</port>
    </enrollment>
  </client>
</ossec_config>
```

> Usar siempre la **IP privada** (`10.0.20.51`), nunca la IP pública  
> del Manager. Apuntar a la IP pública deja el agente en estado `pending`  
> indefinidamente porque el tráfico interno VPC no sale por la IP pública.

## 5.3 Permisos de lectura sobre logs de T-Pot

T-Pot protege sus directorios de datos con el grupo `tpot` (permisos 770/660).  
El proceso `wazuh-logcollector` corre como usuario `wazuh` y necesita  
pertenecer a ese grupo:
```bash
sudo usermod -aG tpot wazuh
sudo systemctl restart wazuh-agent
```

Verificar:
```bash
id wazuh
# groups=... 2000(tpot)
```
## 5.4 Habilitar y arrancar el agente

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

Verificar conexión con el Manager:
```bash
sudo grep "^status" /var/ossec/var/run/wazuh-agentd.state
# → status='connected'
```

## 6. Configuración de Logcollector

## 6.1 Fuentes de log integradas

Agregar los siguientes bloques `<localfile>` dentro de `<ossec_config>`  
en `/var/ossec/etc/ossec.conf` del agente T-Pot:

```xml
<!-- Suricata IDS -->
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/suricata/log/eve.json</location>
  <label key="@source">tpot</label>
</localfile>

<!-- Dionaea embebido en T-Pot -->
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/dionaea/log/dionaea.json</location>
  <label key="@source">tpot</label>
</localfile>

<!-- Honeytrap -->
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/honeytrap/log/attackers.json</location>
  <label key="@source">tpot</label>
</localfile>

<!-- Conpot (ICS/SCADA simulado) -->
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/conpot/log/conpot_IEC104.json</location>
  <label key="@source">tpot</label>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/conpot/log/conpot_ipmi.json</location>
  <label key="@source">tpot</label>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/conpot/log/conpot_guardian_ast.json</location>
  <label key="@source">tpot</label>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/conpot/log/conpot_kamstrup_382.json</location>
  <label key="@source">tpot</label>
</localfile>

<!-- p0f (OS fingerprinting pasivo) -->
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/tpotce/data/p0f/log/p0f.json</location>
  <label key="@source">tpot</label>
</localfile>
```

> **Nota:** No ingerir los logs internos de infraestructura de T-Pot  
> (`~/tpotce/data/elk/log/*`, `nginx/access.log`). Solo añaden ruido  
> sin valor analítico para los objetivos del proyecto.

## 6.2 Reiniciar el agente y validar

```bash
sudo systemctl restart wazuh-agent

# Confirmar que logcollector lee los archivos
sudo grep "Analyzing file" /var/ossec/logs/ossec.log | grep tpotce
```

Salida esperada (una línea por cada fuente configurada):
```bash
wazuh-logcollector: Analyzing file: '/home/ubuntu/tpotce/data/suricata/log/eve.json'
wazuh-logcollector: Analyzing file: '/home/ubuntu/tpotce/data/dionaea/log/dionaea.json'
...
```

## 7. Validación End-to-End

```bash
# 1. T-Pot corriendo
sudo systemctl status tpot --no-pager | grep Active

# 2. Agente conectado
sudo grep "^status" /var/ossec/var/run/wazuh-agentd.state
# → status='connected'

# 3. Permisos correctos
id wazuh | grep tpot
# → 2000(tpot)

# 4. Logcollector activo sin errores de permisos
sudo grep -i "permission denied" /var/ossec/logs/ossec.log | grep tpotce
# → (sin resultados)

# 5. Eventos visibles en Wazuh Dashboard
# Discover → index: wazuh-archives-*
# Filtro:  data.@source:"tpot"
```

## 8. Troubleshooting
| Síntoma                                                    | Causa probable                                            | Solución                                                            |
| ---------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------- |
| SSH en 64295 falla antes de instalar                       | T-Pot aún no ha reasignado el puerto                      | SSH sigue en 22 pre-install; conectar por 22 durante la instalación |
| `Unable to locate package wazuh-agent`                     | Repositorio APT de Wazuh no agregado                      | Seguir los pasos de **5.1** completos                               |
| `gpg: failed to create temporary file — Permission denied` | `gpg` ejecutado sin `sudo` en el pipe                     | Aplicar `sudo` explícitamente a `gpg --dearmor`, no solo al `curl`  |
| Agente en estado `pending`                                 | `<address>` apunta a IP pública del Manager               | Cambiar a IP privada `10.0.20.51` en `ossec.conf`                   |
| `Permission denied` en logcollector                        | Usuario `wazuh` no pertenece al grupo `tpot`              | `sudo usermod -aG tpot wazuh` + reiniciar agente                    |
| No aparecen eventos `data.@source:"tpot"`                  | Label `@source` mal declarado o fuera de `<ossec_config>` | Verificar estructura XML del bloque `<localfile>`                   |
## 9. Capturas de Evidencia

> Ubicación en el repositorio: `screenshots/tpot/`

| Archivo                       | Contenido                                                                |
| ----------------------------- | ------------------------------------------------------------------------ |
| [Agente wazuh tpot activo](../../screenshots/tpot/tpot-wazuh-agent-active.png) | Dashboard Wazuh → Endpoints: agente `ip-10-0-10-76` en estado **active** |
| [Eventos de archivos tpot](../../screenshots/tpot/tpot-archives-eventos.png)   | Discover `wazuh-archives-*` filtrando `data.@source:"tpot"`              |
| [Contenedores tpot](../../screenshots/tpot/tpot-dps-containers.png)     | Salida de `dps` mostrando los contenedores activos                       |
## Referencias

- [T-Pot CE — Repositorio oficial](https://github.com/telekom-security/tpotce)
    
- [T-Pot CE — System Requirements](https://github.com/telekom-security/tpotce#system-requirements)
    
- [Wazuh — Agent installation on Linux](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)
    
- [Wazuh — Localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
