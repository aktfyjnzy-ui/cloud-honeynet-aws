# Despliegue de Dionaea — Honeypot SMB/HTTP/FTP/Malware

> **Instancia:** `i-0e8c4a42243c5d40a` · t3.micro · Ubuntu 24.04 LTS  
> **IP privada:** `10.0.10.154`  
> **Versión Dionaea:** 0.11.0  
> **Fecha de despliegue:** 2026-02-13  
> **Estado al cierre del proyecto:** Operativo (30 días continuos)

---

## Tabla de Contenidos

1. [Descripción](#1-descripción)
2. [Pre-requisitos](#2-pre-requisitos)
3. [Instalación de Dionaea](#3-instalación-de-dionaea)
4. [Configuración](#4-configuración)
5. [Integración con Wazuh Agent](#5-integración-con-wazuh-agent)
6. [Configuración de Logcollector](#6-configuración-de-logcollector)
7. [Captura de Binarios Maliciosos](#7-captura-de-binarios-maliciosos)
8. [Validación End-to-End](#8-validación-end-to-end)
9. [Troubleshooting](#9-troubleshooting)
10. [Capturas de Evidencia](#10-capturas-de-evidencia)

---

## 1. Descripción

Dionaea es un honeypot de baja interacción especializado en la captura de
**malware que se propaga mediante vulnerabilidades de red**. Emula servicios
como SMB, HTTP, FTP y MSSQL para atraer exploits, con capacidad de capturar
y almacenar los binarios maliciosos entregados durante un ataque.

En este proyecto, Dionaea opera como el sensor de mayor volumen de eventos,
siendo responsable del **46.7% del total de capturas** (64,338 de 137,657
eventos), dominado por SMB scanning masivo desde hosts comprometidos.

| Parámetro | Valor |
|:----------|:------|
| Puertos expuestos | TCP/21 (FTP) · TCP/80 (HTTP) · TCP/445 (SMB) · TCP/1433 (MSSQL) |
| Ruta de instalación | `/opt/dionaea` |
| Log JSON | `/opt/dionaea/var/lib/dionaea/dionaea.json` |
| Directorio de binarios | `/opt/dionaea/var/lib/dionaea/binaries/` |
| iHandler activo | `log_json` |

---

## 2. Pre-requisitos

### 2.1 Security Group (`chn-sg-dionaea`)

| Dirección | Protocolo | Puerto(s) | Origen |
|:----------|:----------|:----------|:-------|
| Inbound | TCP | 21, 80, 445, 1433 | `0.0.0.0/0` |
| Inbound | TCP | 22 | `<IP-admin>/32` |
| Outbound | TCP | 1514, 1515 | `chn-sg-wazuh` |

> Durante la instalación abrir temporalmente **Outbound TCP/80 y
> TCP/443** para compilación de dependencias. Cerrar al finalizar.

### 2.2 Conectividad con Wazuh Manager

```bash
nc -zv -w 3 10.0.20.51 1514
nc -zv -w 3 10.0.20.51 1515
# Ambos deben retornar: succeeded!
```
## 3. Instalación de Dionaea

Dionaea 0.11.0 se instala **compilado desde fuente** con el directorio  
de trabajo en `/opt/dionaea`.

## 3.1 Dependencias del sistema
```bash
sudo apt update
sudo apt install -y \
    git cmake build-essential \
    libglib2.0-dev libssl-dev libcurl4-openssl-dev \
    libreadline-dev libsqlite3-dev \
    python3-dev python3-pip python3-setuptools \
    liblcfg-dev libnl-3-dev libnl-genl-3-dev \
    libemu-dev libev-dev libudns-dev \
    libpcap-dev
```

## 3.2 Clonar y compilar
```bash
git clone https://github.com/DinoTools/dionaea /tmp/dionaea-src
cd /tmp/dionaea-src

mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/dionaea ..
make -j$(nproc)
sudo make install
```
## 3.3 Fix del módulo Python (incidente resuelto)

Durante la instalación se produjo un fallo al cargar el módulo Python  
de Dionaea. Solución aplicada:

```bash
# Copiar el paquete Python al directorio correcto
sudo cp -r /tmp/dionaea-src/modules/python/dionaea \
    /opt/dionaea/lib/dionaea/python/dionaea/

# Copiar la extensión compilada
sudo cp /tmp/dionaea-src/build/modules/python/core.cpython-*-x86_64-linux-gnu.so \
    /opt/dionaea/lib/dionaea/python/dionaea/
```
## 3.4 Verificar listeners activos

```bash
sudo /opt/dionaea/bin/dionaea \
    -l /opt/dionaea/var/log/dionaea/ \
    -p /opt/dionaea/var/run/dionaea.pid \
    -D

# Verificar puertos
sudo ss -lntp | grep dionaea
```

Salida esperada:
```bash
LISTEN  0.0.0.0:21    users:(("dionaea",...))
LISTEN  0.0.0.0:80    users:(("dionaea",...))
LISTEN  0.0.0.0:445   users:(("dionaea",...))
LISTEN  0.0.0.0:1433  users:(("dionaea",...))
```

## 4. Configuración

## 4.1 Archivo principal

Verificar en `/opt/dionaea/etc/dionaea/dionaea.cfg`:
```text
[dionaea]
downloads.dir=var/lib/dionaea/binaries/
logging.root=var/log/dionaea/
ihandler_configs=etc/dionaea/ihandlers-enabled/*.yaml
imports=dionaea.log,dionaea.services,dionaea.ihandlers
```

## 4.2 Habilitar salida JSON (`log_json` iHandler)

Crear el directorio de iHandlers habilitados y el archivo de configuración:

```bash
sudo mkdir -p /opt/dionaea/etc/dionaea/ihandlers-enabled

sudo tee /opt/dionaea/etc/dionaea/ihandlers-enabled/log_json.yaml > /dev/null << 'EOF'
- name: log_json
  config:
    filename: "var/lib/dionaea/dionaea.json"
EOF
```

## 4.3 Persistencia como daemon

Arrancar Dionaea como daemon con PID file para control de proceso:
```bash
sudo /opt/dionaea/bin/dionaea \
    -l /opt/dionaea/var/log/dionaea/ \
    -p /opt/dionaea/var/run/dionaea.pid \
    -w /opt/dionaea \
    -D
```

Verificar daemonización (comportamiento esperado: proceso padre + hijo):
```bash
ps aux | grep dionaea
# PID 7380 (PPID=1)  → proceso principal
# PID 7381 (PPID=7380) → proceso hijo
```
## 4.4 Persistencia como servicio systemd

Crear `/etc/systemd/system/dionaea.service`:
```text
[Unit]
Description=Dionaea Malware Capture Honeypot
After=network.target

[Service]
Type=forking
PIDFile=/opt/dionaea/var/run/dionaea.pid
ExecStart=/opt/dionaea/bin/dionaea \
    -l /opt/dionaea/var/log/dionaea/ \
    -p /opt/dionaea/var/run/dionaea.pid \
    -w /opt/dionaea \
    -D
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dionaea
sudo systemctl start dionaea
```

## 5. Integración con Wazuh Agent

## 5.1 Instalación del agente

```bash
# Abrir ventana temporal egress TCP/80,443 en el SG

# Importar GPG key con sudo en ambos lados del pipe
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
    https://packages.wazuh.com/4.x/apt/ stable main" | \
    sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo WAZUH_MANAGER="10.0.20.51" apt install -y wazuh-agent

# Deshabilitar repo para evitar upgrades accidentales
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```
## 5.2 Habilitar y arrancar el agente
```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```
## 5.3 Cerrar ventana temporal de egress

```text
Outbound TCP/1514 → chn-sg-wazuh   (mantener)
Outbound TCP/1515 → chn-sg-wazuh   (mantener)
Outbound TCP/80   → 0.0.0.0/0      (eliminar)
Outbound TCP/443  → 0.0.0.0/0      (eliminar)
```

## 6. Configuración de Logcollector

## 6.1 Configurar localfile en el agente

Editar `/var/ossec/etc/ossec.conf` — agregar dentro de `<ossec_config>`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/dionaea/var/lib/dionaea/dionaea.json</location>
  <label key="@source">dionaea</label>
</localfile>
```

Reiniciar el agente:
```bash
sudo systemctl restart wazuh-agent
```

## 6.2 Validar configuración del agente
```bash
sudo /var/ossec/bin/wazuh-agentd -t
# rc=0 → configuración válida

sudo /var/ossec/bin/wazuh-logcollector -t
# rc=0 → logcollector válido
```
## 6.3 Confirmar que el JSON existe y tiene eventos

El archivo `dionaea.json` no se crea hasta que Dionaea recibe su  
primer evento. Verificar:

```bash
# Esperar al primer evento (puede tardar minutos en un entorno expuesto)
sudo ls -lh /opt/dionaea/var/lib/dionaea/dionaea.json

# Confirmar que el logcollector lo está leyendo
sudo grep "dionaea.json" /var/ossec/logs/ossec.log
# → Analyzing file: '/opt/dionaea/var/lib/dionaea/dionaea.json'
```
## 7. Captura de Binarios Maliciosos

Dionaea está configurado para almacenar binarios maliciosos descargados  
durante ataques en el directorio `binaries/`.
```bash
sudo find /opt/dionaea/var/lib/dionaea/binaries/ \
    -type f -size +0c -printf '%s bytes  %p\n'
```

> **Decisión de diseño:** Con el egress cerrado (solo TCP/1514-1515 hacia  
> Wazuh), Dionaea puede recibir payloads por **upload inbound** pero no  
> puede completar descargas hacia servidores C2 externos. Durante el  
> proyecto se observaron únicamente archivos `.tmp` de 0 bytes, lo que  
> confirma que los atacantes intentaron entregas pull que fueron bloqueadas  
> por el aislamiento de red.
> 
> Esta es una **decisión consciente de seguridad**: habilitar egress general  
> para capturar binarios completos aumentaría el riesgo de usar el honeypot  
> como pivote. El aislamiento se mantuvo como prioridad.

## 8. Validación End-to-End

```bash
# 1. Dionaea corriendo con los puertos correctos
sudo ss -lntp | grep -E ':21|:80|:445|:1433'

# 2. JSON generándose con eventos
sudo tail -5 /opt/dionaea/var/lib/dionaea/dionaea.json

# 3. Agente conectado al Manager
sudo grep "^status" /var/ossec/var/run/wazuh-agentd.state
# → status='connected'

# 4. Logcollector leyendo el archivo
sudo grep "dionaea.json" /var/ossec/logs/ossec.log | tail -3

# 5. Eventos visibles en Wazuh Dashboard
# Discover → index: wazuh-archives-*
# Filtro:  data.@source:"dionaea"
# Campos esperados: data.connection.protocol (smbd / httpd / ftpd / mssqld)
```

## Ejemplo de evento correctamente indexado

```json
{
  "agent.name": "ip-10-0-10-154",
  "location": "/opt/dionaea/var/lib/dionaea/dionaea.json",
  "decoder.name": "json",
  "data.@source": "dionaea",
  "data.connection.protocol": "smbd",
  "data.connection.remote_host": "201.187.98.150"
}
```

## 9. Troubleshooting
| Síntoma                                   | Causa probable                                         | Solución                                                          |
| ----------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------- |
| Dionaea no carga módulo Python            | Extensión `.so` no copiada al directorio correcto      | Aplicar fix de §3.3                                               |
| `dionaea.json` no existe tras arrancar    | Dionaea aún no recibió el primer evento                | Esperar tráfico real o generar un test de conexión en TCP/445     |
| Logcollector no lee el JSON               | Archivo no existía cuando arrancó el agente            | Reiniciar `wazuh-agent` después de confirmar que el JSON existe   |
| Agente en estado `pending`                | `<address>` apunta a IP pública del Manager            | Cambiar a IP privada `10.0.20.51` en `ossec.conf`                 |
| Binarios `.tmp` de 0 bytes en `binaries/` | Egress cerrado impide completar descarga pull desde C2 | Comportamiento esperado con el aislamiento activo; no es un error |
## 10. Capturas de Evidencia

> Ubicación en el repositorio: `screenshots/dionaea/`

| Archivo                          | Contenido                                                                                                   |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `dionaea-wazuh-agent-active.png` | Dashboard Wazuh → Endpoints: agente `ip-10-0-10-154` en estado **active**                                   |
| `dionaea-archives-eventos.png`   | Discover `wazuh-archives-*` filtrando `data.@source:"dionaea"` con campo `data.connection.protocol` visible |
| `dionaea-smb-eventos.png`        | Eventos SMB del hallazgo del Hospital Base Valdivia (más de 64,095 eventos)                                 |
## Referencias

- [Dionaea — Repositorio oficial](https://github.com/DinoTools/dionaea)
    
- [Wazuh — Localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
    
- [MITRE ATT&CK — T1046 Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
    
- [MITRE ATT&CK — T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)