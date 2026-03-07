#!/usr/bin/env python3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import requests.exceptions
import json, time, os, logging, ipaddress
from pathlib import Path
from datetime import datetime, timezone, timedelta
import requests
import pwd

PROJECT_ROOT = Path("/home/ubuntu")
ENV_FILE = PROJECT_ROOT / ".honeynet_ti.env"

CANDIDATES_DIR = PROJECT_ROOT / "outputs" / "ti" / "latest"
ENRICH_ROOT = PROJECT_ROOT / "outputs" / "ti" / "enriched"
LATEST_OUT = ENRICH_ROOT / "latest" / "ti_enriched_latest.jsonl"
RUNS_DIR = ENRICH_ROOT / "runs"
CACHE_FILE = PROJECT_ROOT / "scripts" / "ti" / "cache" / "tienrichment_cache.json"
LOG_FILE = PROJECT_ROOT / "logs" / "tienrichment.log"

# Schema confirmado por tu muestra
IP_FIELD = "src_ip"
SOURCE_FIELD = "@source"

# Cache y cuotas por ejecución (para AbuseIPDB free tier ~1000 req/día)
CACHE_TTL_HOURS = 24
MAX_ABUSE_PER_RUN = 40
MAX_GN_PER_RUN = 200
MAX_OTX_PER_RUN = 20

ABUSE_HIGH_SCORE = 75

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] tienrichment: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

def build_session() -> requests.Session:
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    s = requests.Session()
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    s.mount("https://", adapter)
    return s

SESSION = build_session()

def load_env(path: Path) -> dict:
    env = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env

def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except Exception:
        return {}

def save_cache(cache: dict):
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache))
    tmp.replace(CACHE_FILE)

def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except Exception:
        return False

def newest_candidates_file() -> Path | None:
    files = sorted(CANDIDATES_DIR.glob("ti_candidates_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None

def query_abuseipdb(ip: str, key: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 30}

    try:
        r = SESSION.get(url, headers=headers, params=params, timeout=(3, 20))

        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code == 422:
            try:
                j = r.json() or {}
                detail = None
                if "errors" in j and j["errors"]:
                    detail = j["errors"][0].get("detail")
                return {"error": "http_422", "detail": detail}
            except Exception:
                return {"error": "http_422"}
        if not r.ok:
            return {"error": f"http_{r.status_code}"}

        j = r.json() or {}
        d = j.get("data", {}) or {}

        return {
            "score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "country_code": d.get("countryCode"),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "last_reported_at": d.get("lastReportedAt"),
        }

    except requests.exceptions.ReadTimeout:
        return {"error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": type(e).__name__}

def query_greynoise(ip: str, key: str) -> dict:
    url = f"https://api.greynoise.io/v3/community/ip/{ip}"
    headers = {"key": key, "Accept": "application/json"}

    try:
        r = SESSION.get(url, headers=headers, timeout=(3, 20))

        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code == 404:
            return {"seen": False}
        if not r.ok:
            return {"error": f"http_{r.status_code}"}

        d = r.json() or {}
        return {
            "seen": d.get("seen"),
            "classification": d.get("classification"),
            "name": d.get("name"),
            "last_seen": d.get("last_seen"),
            "noise": d.get("noise"),
            "link": d.get("link"),
        }

    except requests.exceptions.ReadTimeout:
        return {"error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": type(e).__name__}

def query_otx(ip: str, key: str) -> dict:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}
    try:
        r = SESSION.get(url, headers=headers, timeout=(3, 20))
        if r.status_code == 404:
            return {"pulse_count": 0, "tags": []}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if not r.ok:
            return {"error": f"http_{r.status_code}"}

        d = r.json() or {}
        pulse_info = d.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []
        tags = sorted({t for p in pulses for t in (p.get("tags", []) or [])})
        return {"pulse_count": pulse_info.get("count", len(pulses)), "tags": tags}

    except requests.exceptions.ReadTimeout:
        return {"error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": type(e).__name__}

def confidence_from(ti: dict) -> str:
    abuse = ti.get("abuseipdb") or {}
    gn = ti.get("greynoise") or {}
    otx = ti.get("otx") or {}

    abuse_score = abuse.get("score")
    gn_class = gn.get("classification")
    pulse_count = otx.get("pulse_count")

    if (isinstance(abuse_score, int) and abuse_score >= ABUSE_HIGH_SCORE) or gn_class == "malicious" or (isinstance(pulse_count, int) and pulse_count > 0):
        return "high"
    if (isinstance(abuse_score, int) and abuse_score >= 25) or gn_class == "unknown":
        return "medium"
    return "low"

def write_outputs(records: list[dict]):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    run_dir = RUNS_DIR / f"enrichment_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    run_file = run_dir / f"ti_enriched_{ts}.jsonl"
    with run_file.open("w", encoding="utf-8") as fr, LATEST_OUT.open("w", encoding="utf-8") as fl:
        for rec in records:
            line = json.dumps(rec, ensure_ascii=False)
            fr.write(line + "\n")
            fl.write(line + "\n")

    # Dejar outputs legibles por ubuntu (sin exponer secrets: aquí solo hay respuestas TI)
    ubuntu_uid = pwd.getpwnam("ubuntu").pw_uid
    ubuntu_gid = pwd.getpwnam("ubuntu").pw_gid
    for p in [run_file, LATEST_OUT]:
        os.chown(p, ubuntu_uid, ubuntu_gid)
        os.chmod(p, 0o640)

def write_cdb(records: list[dict]):
    # CDB “enriched” para detección: ip:confidence
    cdb_dir = PROJECT_ROOT / "lists" / "cdb"
    cdb_dir.mkdir(parents=True, exist_ok=True)
    out_all = cdb_dir / "honeynet-ti-ip.enriched.list"
    out_top = cdb_dir / "honeynet-ti-ip.enriched.top200.list"

    for p in [out_all, out_top]:
        p.parent.mkdir(parents=True, exist_ok=True)

    with out_all.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(f"{r['ip']}:{r['confidence']}\n")

    high = [r for r in records if r["confidence"] == "high"]
    def abuse_score(r):
        s = (r.get("ti", {}).get("abuseipdb", {}) or {}).get("score")
        return s if isinstance(s, int) else 0
    high_sorted = sorted(high, key=abuse_score, reverse=True)[:200]

    with out_top.open("w", encoding="utf-8") as f:
        for r in high_sorted:
            f.write(f"{r['ip']}:high\n")

    ubuntu_uid = pwd.getpwnam("ubuntu").pw_uid
    ubuntu_gid = pwd.getpwnam("ubuntu").pw_gid
    for p in [out_all, out_top]:
        os.chown(p, ubuntu_uid, ubuntu_gid)
        os.chmod(p, 0o640)

def main():
    if not ENV_FILE.exists():
        logging.error(f"No existe {ENV_FILE}. Crea el .env con permisos 600.")
        return 2

    env = load_env(ENV_FILE)
    abuse_key = env.get("ABUSEIPDB_API_KEY")
    otx_key = env.get("OTX_API_KEY")
    gn_key = env.get("GREYNOISE_API_KEY")

    cand = newest_candidates_file()
    if not cand:
        logging.error(f"No encontré ti_candidates_*.jsonl en {CANDIDATES_DIR}")
        return 2

    cache = load_cache()
    now = datetime.now(timezone.utc)

    abuse_used = gn_used = otx_used = 0
    records = []

    logging.info(f"Input: {cand}")
    with cand.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)

            ip = evt.get(IP_FIELD)
            if not ip or not is_public_ip(ip):
                continue

            src = evt.get(SOURCE_FIELD)
            sample_ts = evt.get("sample_timestamp")
            count = evt.get("count")

            c = cache.get(ip, {})
            last = c.get("last_updated")
            fresh = False
            if last:
                try:
                    last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    fresh = (now - last_dt) < timedelta(hours=CACHE_TTL_HOURS)
                except Exception:
                    fresh = False

            ti = {"abuseipdb": None, "otx": None, "greynoise": None}
            if fresh:
                ti["abuseipdb"] = c.get("abuseipdb")
                ti["otx"] = c.get("otx")
                ti["greynoise"] = c.get("greynoise")
            else:
                if abuse_key and abuse_used < MAX_ABUSE_PER_RUN:
                    ti["abuseipdb"] = query_abuseipdb(ip, abuse_key)
                    abuse_used += 1
                    time.sleep(0.2)
                if gn_key and gn_used < MAX_GN_PER_RUN:
                    ti["greynoise"] = query_greynoise(ip, gn_key)
                    gn_used += 1
                    time.sleep(0.1)
                if otx_key and otx_used < MAX_OTX_PER_RUN:
                    ti["otx"] = query_otx(ip, otx_key)
                    otx_used += 1
                    time.sleep(0.1)

                cache[ip] = {
                    "last_updated": now.isoformat(),
                    "abuseipdb": ti["abuseipdb"],
                    "otx": ti["otx"],
                    "greynoise": ti["greynoise"],
                }

            conf = confidence_from(ti)
            records.append({
                "ip": ip,
                "@source": src or "unknown",
                "source": src or "unknown",
                "sample_timestamp": sample_ts,
                "count": count,
                "ti": ti,
                "confidence": conf,
                "ts_enriched": datetime.now(timezone.utc).isoformat()
            })

    logging.info(f"Enriched IPs: {len(records)} | AbuseIPDB calls: {abuse_used} | GreyNoise calls: {gn_used} | OTX calls: {otx_used}")
    write_outputs(records)
    write_cdb(records)
    save_cache(cache)

    high = sum(1 for r in records if r["confidence"] == "high")
    logging.info(f"High-confidence: {high}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
