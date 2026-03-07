#!/usr/bin/env python3
import argparse, json, ipaddress, os, datetime
from collections import Counter, defaultdict

ALLOWED_SOURCES = {"tpot", "cowrie", "dionaea"}

def is_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except Exception:
        return False

def get_src_ip(e: dict) -> str | None:
    """Extrae src_ip de forma ULTRA ROBUSTA para Cowrie / Dionaea / T-Pot"""
    data = e.get("data", {}) or {}
    full_log = e.get("full_log", "")

    # 1. Campos directos (Cowrie funciona perfecto aquí)
    candidates = [
        data.get("src_ip"),
        data.get("srcip"),
        e.get("src_ip"),
        e.get("srcip"),
        data.get("connection", {}).get("src_ip"),
        data.get("alert", {}).get("source", {}).get("ip") if isinstance(data.get("alert"), dict) else None,
        data.get("flow", {}).get("src_ip") if isinstance(data.get("flow"), dict) else None,
        data.get("src", {}).get("ip") if isinstance(data.get("src"), dict) else None,
    ]

    # 2. Parsear full_log como JSON (clave para Dionaea y Suricata de T-Pot)
    if isinstance(full_log, str) and full_log.strip().startswith("{"):
        try:
            log_json = json.loads(full_log)
            candidates += [
                log_json.get("src_ip"),
                log_json.get("connection", {}).get("src_ip"),
                log_json.get("ftp", {}).get("src_ip") if isinstance(log_json.get("ftp"), dict) else None,
                log_json.get("src_ip"),
                log_json.get("src", {}).get("ip") if isinstance(log_json.get("src"), dict) else None,
            ]
        except:
            pass

    # 3. Fallback regex IPv4 (por si Suricata está en texto plano)
    if not any(isinstance(c, str) and is_public_ip(c) for c in candidates if c):
        import re
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', full_log)
        for ip_str in ips:
            if is_public_ip(ip_str):
                return ip_str

    for ip in candidates:
        if isinstance(ip, str) and is_public_ip(ip):
            return ip
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="JSONL desde Wazuh archives")
    ap.add_argument("--outdir", default="outputs/ti", help="Directorio de salida")
    ap.add_argument("--top", type=int, default=20, help="Top N IPs")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    day = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d")

    totals = Counter()
    public_totals = Counter()
    per_source_ip = defaultdict(Counter)
    samples = {}  # (source, ip) -> sample

    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue

            # === DETECCIÓN POR AGENT.NAME ===
            agent_name = e.get("agent", {}).get("name", "")
            if agent_name == "ip-10-0-10-36":
                src = "cowrie"
            elif agent_name == "ip-10-0-10-154":
                src = "dionaea"
            elif agent_name == "ip-10-0-10-76":
                src = "tpot"
            else:
                continue

            if src not in ALLOWED_SOURCES:
                continue

            totals[src] += 1

            ip = get_src_ip(e)
            if not ip:
                continue

            public_totals[src] += 1
            per_source_ip[src][ip] += 1

            key = (src, ip)
            if key not in samples:
                rule = e.get("rule", {}) or {}
                agent = e.get("agent", {}) or {}
                samples[key] = {
                    "@source": src,
                    "src_ip": ip,
                    "sample_timestamp": e.get("timestamp"),
                    "sample_rule_id": rule.get("id"),
                    "sample_rule_desc": rule.get("description"),
                    "sample_agent_id": agent.get("id"),
                    "sample_agent_name": agent_name,
                }

    # candidates JSONL
    candidates_path = os.path.join(args.outdir, f"ti_candidates_{day}.jsonl")
    with open(candidates_path, "w", encoding="utf-8") as o:
        for src in sorted(per_source_ip.keys()):
            for ip, cnt in per_source_ip[src].most_common():
                rec = dict(samples[(src, ip)])
                rec["count"] = cnt
                rec["generated_at_utc"] = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00","Z")
                o.write(json.dumps(rec) + "\n")

    # top TXT
    top_path = os.path.join(args.outdir, f"ti_top_{day}.txt")
    with open(top_path, "w", encoding="utf-8") as o:
        o.write(f"Input: {args.input}\n")
        o.write(f"Generated: {datetime.datetime.now(datetime.UTC).isoformat().replace('+00:00','Z')}\n\n")
        for src in sorted(totals.keys()):
            o.write(f"[{src}] total_events={totals[src]} public_ip_events={public_totals[src]}\n")
            for ip, cnt in per_source_ip[src].most_common(args.top):
                o.write(f" {ip} count={cnt}\n")
            o.write("\n")

    print(f"OK: candidates={candidates_path}")
    print(f"OK: top={top_path}")
    print("Stats totals:", dict(totals))
    print("Stats public:", dict(public_totals))

if __name__ == "__main__":
    main()
