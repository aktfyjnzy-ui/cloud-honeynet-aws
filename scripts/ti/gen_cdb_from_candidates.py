#!/usr/bin/env python3
import argparse, json
from collections import defaultdict

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="outputs/ti/ti_candidates_YYYYMMDD.jsonl")
    ap.add_argument("--output", required=True, help="Salida FULL, ej: lists/cdb/honeynet-ti-ip.list")
    ap.add_argument("--top-output", default="", help="Salida TOP N, ej: lists/cdb/honeynet-ti-ip.top200.list")
    ap.add_argument("--min-count", type=int, default=2, help="Umbral mínimo de ocurrencias por IP")
    ap.add_argument("--max-keys", type=int, default=0, help="Máximo de keys para top-output (0 = no generar top)")
    args = ap.parse_args()

    meta = defaultdict(lambda: {"count": 0, "sources": set()})

    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            e=json.loads(line)
            ip=e.get("src_ip")
            src=e.get("@source")
            cnt=int(e.get("count", 1))
            if not ip or not src:
                continue
            meta[ip]["count"] += cnt
            meta[ip]["sources"].add(src)

    items=[]
    for ip, m in meta.items():
        if m["count"] < args.min_count:
            continue
        srcs=",".join(sorted(m["sources"]))
        val=f"src={srcs};count={m['count']};tag=ti_candidate"
        items.append((m["count"], ip, val))

    # Orden: mayor conteo primero, luego IP para estabilidad
    items.sort(key=lambda x: (-x[0], x[1]))

    # FULL
    with open(args.output, "w", encoding="utf-8") as o:
        for _, ip, val in items:
            o.write(f"{ip}:{val}\n")
    print(f"OK: generado FULL {args.output} ({len(items)} keys)")

    # TOP N (opcional)
    if args.max_keys and args.top_output:
        with open(args.top_output, "w", encoding="utf-8") as o:
            for _, ip, val in items[:args.max_keys]:
                o.write(f"{ip}:{val}\n")
        print(f"OK: generado TOP{args.max_keys} {args.top_output} ({min(len(items), args.max_keys)} keys)")

if __name__ == "__main__":
    main()
