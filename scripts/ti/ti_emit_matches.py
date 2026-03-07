#!/usr/bin/env python3
import json, socket
from pathlib import Path
from datetime import datetime, timezone

import glob
_cands = sorted(glob.glob("/home/ubuntu/outputs/ti/latest/ti_candidates_*.jsonl"))
if not _cands:
    raise SystemExit("ERROR: no ti_candidates_*.jsonl found in latest/")
CAND = Path(_cands[-1])
print(f"[ti_emit] Using candidates: {CAND}")
TOP  = Path("/var/ossec/etc/lists/honeynet-ti-ip.enriched.top200")
OUT  = Path("/var/log/honeynet-ti/ti_matches.jsonl")
SEEN = Path("/var/log/honeynet-ti/ti_seen_high.txt")
WAZUH_SOCKET = "/var/ossec/queue/sockets/queue"

def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def send_to_wazuh(event_dict: dict):
    """Envía el evento directamente al socket de analysisd."""
    payload = json.dumps(event_dict, separators=(",", ":"))
    # Formato: "1:[location]:[source]:[message]"
    msg = f"1:[honeynet-ti]:/var/log/honeynet-ti/ti_matches.jsonl:{payload}"
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(WAZUH_SOCKET)
        sock.send(msg.encode("utf-8"))
        sock.close()
    except Exception as e:
        print(f"WARN: socket send failed: {e}")

def load_top(path: Path):
    d = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        ip, conf = line.split(":", 1)
        d[ip.strip()] = conf.strip()
    return d

def load_seen(path: Path):
    if not path.exists():
        return set()
    return {l.strip() for l in path.read_text().splitlines() if l.strip()}

top = load_top(TOP)
seen = load_seen(SEEN)

if not CAND.exists():
    raise SystemExit(f"ERROR: candidates not found: {CAND}")

OUT.parent.mkdir(parents=True, exist_ok=True)

written = 0
with CAND.open() as fin, OUT.open("a") as fout:
    for line in fin:
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        ip = obj.get("src_ip")
        if ip in top and ip not in seen:
            obj["ti"] = {
                "match": "true",          # string para match de regla Wazuh
                "confidence": top[ip],
                "list": TOP.name,
                "emitted_at_utc": now_utc()
            }
            event_json = json.dumps(obj, separators=(",", ":"))
            fout.write(event_json + "\n")   # auditoría local
            send_to_wazuh(obj)              # directo a analysisd
            seen.add(ip)
            written += 1


SEEN.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""))
print(f"OK appended={written} out={OUT} seen={len(seen)}")
