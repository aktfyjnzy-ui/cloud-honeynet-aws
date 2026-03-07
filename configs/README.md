# configs/ — Archivos de Configuración

Este directorio centraliza todos los archivos de configuración del
proyecto Cloud HoneyNet AWS, organizados por componente. Están listos
para ser copiados directamente a las rutas de destino en cada instancia.

---

## Estructura

configs/  
└── wazuh/  
├── README.md Este archivo  
├── 100-cowrie_rules.xml Reglas de detección — Cowrie SSH/Telnet  
├── local_rules.xml Reglas TI + T-Pot + Dionaea + correlación  
├── ossec-agent-cowrie.conf Fragmento localfile para el agente Cowrie  
├── ossec-agent-tpot.conf Fragmento localfile para el agente T-Pot  
└── ossec-agent-dionaea.conf Fragmento localfile para el agente Dionaea


---

## Reglas del Manager

### `100-cowrie_rules.xml`

**Destino en el Manager:** `/var/ossec/etc/rules/100-cowrie_rules.xml`

| ID | Descripción | Nivel |
|:---|:------------|------:|
| 100500 | Parent rule — todos los eventos Cowrie (`^cowrie\.`) | 0 |
| 100501 | Session connect (`no_log`) | 3 |
| 100502 | Login failed — base correlación (`no_log`) | 3 |
| 100503 | Login success | 8 |
| 100504 | Brute force SSH (≥10/180s) | 10 |
| 100505 | Command input — base correlación (`noalert`) | 1 |
| 100506 | Session closed (`no_log`) | 2 |
| 100507 | Brute force Telnet (≥10/180s) | 10 |
| 100511 | Download + execute (curl/wget pipe a shell) | 13 |
| 100512 | Reverse shell / interactive exec | 14 |
| 100513 | Preparación / persistencia (chmod, crontab…) | 11 |

```bash
# Desplegar en el Manager
sudo cp configs/wazuh/100-cowrie_rules.xml /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```


---

## `local_rules.xml`

**Destino en el Manager:** `/var/ossec/etc/rules/local_rules.xml`

| Bloque            | IDs                    | Cobertura                                      |
| ----------------- | ---------------------- | ---------------------------------------------- |
|                   |                        |                                                |
| Bloque            | IDs                    | Cobertura                                      |
| TI Cowrie         | 100550, 100578         | CDB match + alerta TI (hijo de 100500)         |
| Parent T-Pot      | 100568                 | Todos los eventos T-Pot (`@source: tpot`)      |
| Parent Dionaea    | 100582                 | Todos los eventos Dionaea (`@source: dionaea`) |
| TI T-Pot          | 100551, 100579         | CDB match + alerta TI                          |
| TI Dionaea        | 100553, 100580         | CDB match + alerta TI                          |
| T-Pot proto       | 100571, 100572, 100581 | RDP · SSH · NMAP/CINS scans                    |
| Thresholds        | 100573, 100574, 100575 | Brute-force y repetición por protocolo         |
| Correlación       | 100576                 | Multi-honeypot ≥2 sensores/600s (T1595)        |
| Cowrie dropper    | 100577                 | wget/curl/tftp/python en sesión activa         |
| Dionaea           | 100583, 100584         | Conexión genérica · SMB TCP/445                |
| Suricata override | 100585                 | Alerta Suricata T-Pot con MITRE T1046          |

> **Orden de carga crítico:** `local_rules.xml` depende de `100500`  
> definido en `100-cowrie_rules.xml`. Wazuh carga los archivos en orden  
> numérico — `100-cowrie_rules.xml` siempre se carga primero.

```bash
# Desplegar en el Manager
sudo cp configs/wazuh/local_rules.xml /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

---

## Configuración de Agentes

Fragmentos del bloque `<localfile>` para incluir en  
`/var/ossec/etc/ossec.conf` de cada agente sensor.

---

## `ossec-agent-cowrie.conf`

**Destino:** `/var/ossec/etc/ossec.conf` en `ip-10-0-10-36`
```xml
<!-- HoneyNet: Cowrie SSH/Telnet Honeypot -->
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

  <localfile>
    <log_format>json</log_format>
    <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>
    <label key="@source">cowrie</label>
  </localfile>
</ossec_config>
```

---

## `ossec-agent-tpot.conf`

**Destino:** `/var/ossec/etc/ossec.conf` en `ip-10-0-10-76`
```xml
<!-- HoneyNet: T-Pot CE Multi-Honeypot -->
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

  <!-- Conpot ICS/SCADA -->
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

  <!-- p0f OS fingerprinting pasivo -->
  <localfile>
    <log_format>json</log_format>
    <location>/home/ubuntu/tpotce/data/p0f/log/p0f.json</location>
    <label key="@source">tpot</label>
  </localfile>
</ossec_config>
```

> El usuario `wazuh` debe pertenecer al grupo `tpot` para poder  
> leer estos archivos:

```bash
sudo usermod -aG tpot wazuh && sudo systemctl restart wazuh-agent
```

---

## `ossec-agent-dionaea.conf`

**Destino:** `/var/ossec/etc/ossec.conf` en `ip-10-0-10-154`
```xml
<!-- HoneyNet: Dionaea Malware Capture Honeypot -->
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

  <localfile>
    <log_format>json</log_format>
    <location>/opt/dionaea/var/lib/dionaea/dionaea.json</location>
    <label key="@source">dionaea</label>
  </localfile>
</ossec_config>
```

## Aplicar Todo desde Cero

Secuencia completa para desplegar todas las configuraciones en un  
entorno nuevo:

```bash
# 1. Reglas en el Manager
sudo cp configs/wazuh/100-cowrie_rules.xml /var/ossec/etc/rules/
sudo cp configs/wazuh/local_rules.xml      /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager

# 2. Configuración de agentes (ejecutar en cada sensor)
# En Cowrie (ip-10-0-10-36):
#   Fusionar bloque <localfile> de ossec-agent-cowrie.conf en ossec.conf
#   sudo systemctl restart wazuh-agent

# En T-Pot (ip-10-0-10-76):
#   Fusionar bloque <localfile> de ossec-agent-tpot.conf en ossec.conf
#   sudo usermod -aG tpot wazuh
#   sudo systemctl restart wazuh-agent

# En Dionaea (ip-10-0-10-154):
#   Fusionar bloque <localfile> de ossec-agent-dionaea.conf en ossec.conf
#   sudo systemctl restart wazuh-agent

# 3. Verificar agentes activos desde el Manager
sudo /var/ossec/bin/agent_control -l | grep Active
```

---

## Referencias

- [Reglas — documentación completa](cloud-honeynet-aws/docs/02-wazuh-integracion/reglas-custom)
    
- [Despliegue Cowrie](cloud-honeynet-aws/docs/01-despliegue/cowrie)
    
- [Despliegue T-Pot](cloud-honeynet-aws/docs/01-despliegue/tpot)
    
- [Despliegue Dionaea](cloud-honeynet-aws/docs/01-despliegue/dionaea)
    
- [Despliegue Wazuh Stack](cloud-honeynet-aws/docs/01-despliegue/wazuh-stack)
    
- [Wazuh — ossec.conf reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html)