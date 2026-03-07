# Despliegue de Cowrie — SSH/Telnet Honeypot

> **Instancia:** `i-0d96a8152d9c004ec` · t3.micro · Ubuntu 22.04 LTS  
> **IP privada:** `10.0.10.36`  
> **Fecha de despliegue:** 2026-02-06  
> **Estado al cierre del proyecto:** Operativo (30 días continuos)

---

## Tabla de Contenidos

1. [Descripción](#1-descripción)
2. [Pre-requisitos](#2-pre-requisitos)
3. [Instalación de Cowrie](#3-instalación-de-cowrie)
4. [Configuración](#4-configuración)
5. [Separación Admin vs Honeypot](#5-separación-admin-vs-honeypot)
6. [Integración con Wazuh Agent](#6-integración-con-wazuh-agent)
7. [Reglas Custom en Wazuh Manager](#7-reglas-custom-en-wazuh-manager)
8. [Validación End-to-End](#8-validación-end-to-end)
9. [Troubleshooting](#9-troubleshooting)
10. [Capturas de Evidencia](#10-capturas-de-evidencia)

---

## 1. Descripción

Cowrie es un honeypot de media interacción para los protocolos **SSH** y
**Telnet**. Emula un sistema Linux completo, registra todas las sesiones,
captura credenciales intentadas, comandos ejecutados y archivos descargados
por los atacantes.

En este proyecto, Cowrie opera como el sensor principal de análisis de
comportamiento post-autenticación, siendo la única fuente con capacidad
de capturar **sesiones interactivas completas** (TTY logging).

| Parámetro | Valor |
|:----------|:------|
| Puerto honeypot SSH | TCP/22 (redireccionado → 2222) |
| Puerto honeypot Telnet | TCP/23 (redireccionado → 2223) |
| Puerto admin SSH | TCP/22222 |
| Ruta de instalación | `/home/cowrie/cowrie` |
| Usuario de servicio | `cowrie` |
| Log JSON | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |

---

## 2. Pre-requisitos

### 2.1 Security Group (`chn-sg-cowrie`)

Verificar que el SG tenga configuradas las siguientes reglas antes de
comenzar la instalación:

| Dirección | Protocolo | Puerto | Origen |
|:----------|:----------|:-------|:-------|
| Inbound | TCP | 22, 23 | `0.0.0.0/0` |
| Inbound | TCP | 22222 | `<IP-admin>/32` |
| Outbound | TCP | 1514, 1515 | `chn-sg-wazuh` |

> Durante la instalación es necesario abrir temporalmente
> **Outbound TCP/80 y TCP/443** para descarga de dependencias.
> Cerrar esta ventana inmediatamente al finalizar.

### 2.2 Conectividad con Wazuh Manager

Antes de instalar el agente, validar alcanzabilidad desde la EC2 de Cowrie:

```bash
nc -zv -w 3 10.0.20.51 1514
nc -zv -w 3 10.0.20.51 1515
```

Salida esperada:
```bash
Connection to 10.0.20.51 1514 port [tcp/*] succeeded!
Connection to 10.0.20.51 1515 port [tcp/*] succeeded!
```
## 3. Instalación de Cowrie

## 3.1 Dependencias del sistema
```bash
sudo apt update
sudo apt install -y \
    git python3 python3-venv python3-pip \
    build-essential libssl-dev libffi-dev \
    python3-dev libpython3-dev
```
## 3.2 Usuario de servicio dedicado
```bash
sudo adduser --disabled-password cowrie
sudo su - cowrie
```
## 3.3 Clonar repositorio y crear entorno virtual
```bash
# Como usuario cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie

python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m pip install -e .
```

Esto genera los entrypoints `cowrie`, `createfs`, `fsctl` y `playlog`  
en `cowrie-env/bin/`.

Editar `etc/cowrie.cfg` y agregar/verificar:
```text
[honeypot]
# Emula Ubuntu 22.04 LTS con OpenSSH 8.9
hostname = ubuntu
kernel_version = 5.15.0-92-generic
kernel_build_string = #102-Ubuntu SMP Wed Jan 10 09:33:48 UTC 2024
hardware_platform = x86_64
operating_system = GNU/Linux

[ssh]
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6

[telnet]
enabled = true

[output_jsonlog]
enabled = true
```
## 3.5 Primer arranque y validación

```bash
source cowrie-env/bin/activate cowrie start cowrie status
```

Salida esperada:
```bash
cowrie is running (PID: 5230)
```

Verificar que los puertos estén activos:
```bash
ss -lntp | grep -E ':2222|:2223'
```

```bash
LISTEN  0.0.0.0:2222  users:(("python3",...))
LISTEN  0.0.0.0:2223  users:(("python3",...))
```

Verificar escritura de logs:
```bash
tail -f ~/cowrie/var/log/cowrie/cowrie.json
```

## 4. Configuración

## 4.1 Persistencia como servicio systemd

Crear `/etc/systemd/system/cowrie.service` como **root**:
```text
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
WorkingDirectory=/home/cowrie/cowrie
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cowrie
sudo systemctl start cowrie
```
## 5. Separación Admin vs Honeypot

Cowrie corre internamente en los puertos **2222** (SSH) y **2223** (Telnet).  
El tráfico público que llega a los puertos estándar **22** y **23** se  
redirige mediante reglas `iptables` (NAT PREROUTING), manteniendo el  
puerto **22222** exclusivo para administración.

## 5.1 Reglas iptables
```bash
# Redirigir tráfico honeypot
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
```
## 5.2 Persistencia de reglas iptables
```bash
sudo apt install -y iptables-persistent sudo netfilter-persistent save
```
## 5.3 Configurar SSH administrativo en puerto alterno

Editar `/etc/ssh/sshd_config`:
```bash
sudo sed -i 's/^#Port 22/Port 22222/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

> **Verificar que el SG tenga TCP/22222 abierto hacia tu IP antes de  
> reiniciar sshd**, o perderás el acceso administrativo.

## 5.4 Validación
```bash
# Verificar NAT activo
sudo iptables -t nat -L PREROUTING --line-numbers

# Confirmar que Cowrie registra IPs externas reales
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json | \
    python3 -m json.tool | grep src_ip
```
## 6. Integración con Wazuh Agent

## 6.1 Instalación del agente
```bash
# Abrir ventana temporal egress TCP/80,443 en el SG antes de ejecutar

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
## 6.2 Configurar localfile en el agente

Editar `/var/ossec/etc/ossec.conf` — agregar dentro de `<ossec_config>`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>
  <label key="@source">cowrie</label>
</localfile>
```

> El bloque `<localfile>` debe estar **dentro** de `<ossec_config>`.  
> Un XML mal formado (bloque fuera de la etiqueta raíz) impide que el  
> agente arranque. Validar con:

```bash
sudo /var/ossec/bin/wazuh-agentd -t
```

## 6.3 Habilitar y arrancar el agente
```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```
## 6.4 Cerrar ventana temporal de egress

Una vez instalado el agente, restaurar el SG a egress mínimo:

- TCP/1514 → `chn-sg-wazuh`
    
- TCP/1515 → `chn-sg-wazuh`
    
- Eliminar TCP/80 y TCP/443 salientes
    

## 6.5 Habilitar archiving en Wazuh Manager

En el **Wazuh Manager** (no en el agente), editar  
`/var/ossec/etc/ossec.conf`:
```xml
<global>
  <logall>no</logall>
  <logall_json>yes</logall_json>
</global>
```

Habilitar el módulo archives en Filebeat del Manager:
```bash
sudo sed -i 's/archives.enabled: false/archives.enabled: true/' \
    /etc/filebeat/modules.d/wazuh.yml
sudo systemctl restart filebeat
sudo systemctl restart wazuh-manager
```

Esto crea el índice `wazuh-archives-4.x-YYYY.MM.DD` en OpenSearch y  
permite buscar **todos** los eventos (no solo los que generan alerta)  
en el Dashboard bajo el index pattern `wazuh-archives-*`.

---

## 7. Reglas Custom en Wazuh Manager

Ver archivo completo: [`configs/100-cowrie_rules.xml`](../../configs/100-cowrie_rules.xml)

## Resumen de reglas implementadas

| Rule ID | Evento Cowrie                          | Nivel | MITRE        | Acción                           |
| ------- | -------------------------------------- | ----- | ------------ | -------------------------------- |
| 100500  | `cowrie.*` (grouping base)             | —     | —            | Base decoder, sin alerta         |
| 100501  | `cowrie.session.connect`               | —     | —            | `no_log` (reduce ruido)          |
| 100502  | `cowrie.login.failed`                  | 3     | —            | Base correlación, `noalert`      |
| 100503  | `cowrie.login.success`                 | 8     | T1078        | Alerta: acceso exitoso           |
| 100504  | Brute force SSH (≥10 en 180s)          | 10    | T1110.001    | Alerta: fuerza bruta SSH         |
| 100505  | `cowrie.command.input` (base)          | —     | —            | `noalert`, base para correlación |
| 100506  | `cowrie.session.closed`                | —     | —            | `no_log` (reduce ruido)          |
| 100507  | Brute force Telnet (≥10 en 180s)       | 10    | T1110.001    | Alerta: fuerza bruta Telnet      |
| 100511  | `curl\|wget ... \| sh` (download+exec) | 12    | T1059, T1105 | Alta fidelidad                   |
| 100512  | Reverse shell / interacción sospechosa | 12    | T1059        | Alta fidelidad                   |
| 100513  | Preparación / persistencia             | 10    | T1059        | Alta fidelidad                   |
## Aplicar las reglas en el Manager
```bash
sudo cp configs/wazuh/100-cowrie_rules.xml \
    /var/ossec/etc/rules/100-cowrie_rules.xml

sudo systemctl restart wazuh-manager
```

## Validar con wazuh-logtest
```bash
sudo /var/ossec/bin/wazuh-logtest
```

Pegar un evento de prueba:
```json
{"eventid":"cowrie.login.failed","src_ip":"1.2.3.4","username":"root","password":"admin","timestamp":"2026-02-06T10:00:00Z","@source":"cowrie"}
```

Salida esperada (Phase 3):
```bash
**Phase 3: Completed filtering (rules).
       Rule id: '100504'
       Level: '10'
       Description: 'Cowrie: SSH brute force attempt'
       ...
       mitre.id: 'T1110.001'
```
## 8. Validación End-to-End

Una vez completados todos los pasos, verificar el pipeline completo:
```bash
# 1. Cowrie corriendo
cowrie status
# → cowrie is running (PID: XXXX)

# 2. NAT activo
sudo iptables -t nat -L PREROUTING -n
# → tcp dpt:22 redir ports 2222
# → tcp dpt:23 redir ports 2223

# 3. Agente conectado al Manager
sudo grep "^status" /var/ossec/var/run/wazuh-agentd.state
# → status='connected'

# 4. Logcollector leyendo el JSON de Cowrie
sudo grep "cowrie.json" /var/ossec/logs/ossec.log
# → Analyzing file: '/home/cowrie/cowrie/var/log/cowrie/cowrie.json'

# 5. Eventos visibles en Wazuh (desde Manager)
# Dashboard → Discover → index: wazuh-archives-*
# Filtro: data.@source:"cowrie"
```
## 9. Troubleshooting
| Síntoma                                   | Causa probable                                           | Solución                                                                                     |
| ----------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `wazuh-agent` no arranca                  | XML mal formado en `ossec.conf`                          | Ejecutar `wazuh-agentd -t` y revisar el error de parsing                                     |
| Agente en estado `pending`                | Manager no recibe el enrollment                          | Verificar que `<address>` en el agente apunta a IP **privada** `10.0.20.51`, no a la pública |
| No aparecen eventos en `wazuh-archives-*` | `logall_json` deshabilitado                              | Habilitar en Manager + reiniciar filebeat                                                    |
| Cowrie no registra IPs externas reales    | NAT PREROUTING no activo                                 | Verificar `iptables -t nat -L PREROUTING`                                                    |
| Regla de brute force no dispara           | `noalert` en regla base 100502 rompe correlación         | Verificar orden de reglas: 100502 debe existir como base con `noalert`, no con `no_log`      |
| `Field 'protocol' is static` en regla     | Uso incorrecto de `<field name="protocol">` en regla XML | Usar la etiqueta `<protocol>` directamente, no como campo dinámico                           |
## 10. Capturas de Evidencia

> Ubicación en el repositorio: `screenshots/cowrie/`

| Archivo                             | Contenido                                                                                                                   |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `cowrie-wazuh-agent-active.png`     | Dashboard Wazuh → Endpoints: agente `ip-10-0-10-36` en estado **active**                                                    |
| `cowrie-archives-eventos.png`       | Discover `wazuh-archives-*` filtrando `data.@source:"cowrie"` con eventos `cowrie.session.connect` y `cowrie.command.input` |
| `cowrie-alerts-brute.png`           | Discover `wazuh-alerts-*` con alertas (brute force SSH)                                                                     |
| `cowrie-credenciales-dashboard.png` | Dashboard con ranking de credenciales capturadas                                                                            |
## Referencias

- [Cowrie — Documentación oficial](https://github.com/cowrie/cowrie)
    
- [Wazuh — Localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
    
- [Wazuh — Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
    
- [MITRE ATT&CK — T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    
- [MITRE ATT&CK — T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
