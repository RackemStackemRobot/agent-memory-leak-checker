import argparse
import json
from collections import defaultdict


SUSPICIOUS_KEY_PREFIXES = ("auth.", "token", "secret", "apikey", "api_key", "jwt")


def is_session_key(key: str) -> bool:
    return key.startswith("session.")


def is_suspicious_key(key: str) -> bool:
    k = key.lower()
    return k.startswith(SUSPICIOUS_KEY_PREFIXES)


def main() -> int:
    ap = argparse.ArgumentParser(description="Agent Memory Leak Checker (MVP)")
    ap.add_argument("--log", required=True, help="Path to JSONL memory log file")
    ap.add_argument("--out", required=False, help="Optional path to write JSON report")
    args = ap.parse_args()

    events = []
    total = 0
    reads = 0
    writes = 0

    with open(args.log, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue

            total += 1
            ev = obj.get("event")
            if ev == "memory_read":
                reads += 1
            elif ev == "memory_write":
                writes += 1

            events.append(obj)

    writes_by_key = defaultdict(list)
    reads_by_key = defaultdict(list)

    for e in events:
        ev = e.get("event")
        key = e.get("key")
        if not isinstance(key, str) or not key.strip():
            continue
        key = key.strip()

        if ev == "memory_write":
            writes_by_key[key].append(e)
        elif ev == "memory_read":
            reads_by_key[key].append(e)

    cross_user_findings = []
    cross_trace_session_findings = []
    suspicious_reads_findings = []

    # Cross-user key reuse
    for key, rlist in reads_by_key.items():
        wlist = writes_by_key.get(key, [])
        if not wlist:
            continue

        writer_users = set()
        writer_traces = set()
        for w in wlist:
            uid = w.get("user_id")
            tid = w.get("trace_id")
            if isinstance(uid, str) and uid.strip():
                writer_users.add(uid.strip())
            if isinstance(tid, str) and tid.strip():
                writer_traces.add(tid.strip())

        for r in rlist:
            r_uid = r.get("user_id")
            r_tid = r.get("trace_id")
            if not isinstance(r_uid, str) or not r_uid.strip():
                continue
            r_uid = r_uid.strip()

            if r_uid not in writer_users:
                cross_user_findings.append(
                    {
                        "kind": "cross_user_key_reuse",
                        "key": key,
                        "read_user": r_uid,
                        "read_trace": r_tid,
                        "writer_users": sorted(list(writer_users)),
                        "writer_traces": sorted(list(writer_traces)),
                        "read_preview": str(r.get("value_preview", ""))[:160],
                    }
                )

    # Cross-trace session key reuse
    all_keys = set(list(writes_by_key.keys()) + list(reads_by_key.keys()))
    for key in all_keys:
        if not isinstance(key, str):
            continue
        if not is_session_key(key):
            continue

        trace_ids = set()
        for e in writes_by_key.get(key, []):
            tid = e.get("trace_id")
            if isinstance(tid, str) and tid.strip():
                trace_ids.add(tid.strip())
        for e in reads_by_key.get(key, []):
            tid = e.get("trace_id")
            if isinstance(tid, str) and tid.strip():
                trace_ids.add(tid.strip())

        if len(trace_ids) > 1:
            cross_trace_session_findings.append(
                {
                    "kind": "cross_trace_session_key_reuse",
                    "key": key,
                    "trace_ids": sorted(list(trace_ids)),
                }
            )

    # Suspicious key reads (auth/token/etc)
    for key, rlist in reads_by_key.items():
        if not is_suspicious_key(key):
            continue

        wlist = writes_by_key.get(key, [])
        if not wlist:
            continue

        writer_users = set()
        for w in wlist:
            uid = w.get("user_id")
            if isinstance(uid, str) and uid.strip():
                writer_users.add(uid.strip())

        for r in rlist:
            r_uid = r.get("user_id")
            if not isinstance(r_uid, str) or not r_uid.strip():
                continue
            r_uid = r_uid.strip()

            if r_uid not in writer_users:
                suspicious_reads_findings.append(
                    {
                        "kind": "suspicious_key_read_cross_user",
                        "key": key,
                        "read_user": r_uid,
                        "read_trace": r.get("trace_id"),
                        "writer_users": sorted(list(writer_users)),
                        "read_preview": str(r.get("value_preview", ""))[:160],
                    }
                )

    print("")
    print("Agent Memory Leak Checker")
    print(f"Events loaded: {total} (writes={writes}, reads={reads})")
    print("")
    print("Findings")
    print("--------")
    print(f"Cross-user key reuse: {len(cross_user_findings)}")
    print(f"Cross-trace session key reuse: {len(cross_trace_session_findings)}")
    print(f"Suspicious key reads (auth/token/etc): {len(suspicious_reads_findings)}")
    print("")

    if cross_user_findings:
        print("Cross-user key reuse details")
        print("----------------------------")
        for fnd in cross_user_findings[:20]:
            print(f"- key={fnd['key']}")
            print(f"  read_user={fnd['read_user']} read_trace={fnd.get('read_trace')}")
            print(f"  writer_users={', '.join(fnd['writer_users'])}")
            if fnd.get("read_preview"):
                print(f"  read_preview={fnd.get('read_preview')}")
        print("")

    if cross_trace_session_findings:
        print("Cross-trace session key reuse details")
        print("------------------------------------")
        for fnd in cross_trace_session_findings[:20]:
            print(f"- key={fnd['key']} trace_ids={', '.join(fnd['trace_ids'])}")
        print("")

    if suspicious_reads_findings:
        print("Suspicious key read details")
        print("---------------------------")
        for fnd in suspicious_reads_findings[:20]:
            print(f"- key={fnd['key']}")
            print(f"  read_user={fnd['read_user']} writer_users={', '.join(fnd['writer_users'])}")
            if fnd.get("read_preview"):
                print(f"  read_preview={fnd.get('read_preview')}")
        print("")

    if not (cross_user_findings or cross_trace_session_findings or suspicious_reads_findings):
        print("No obvious memory leakage signals detected.")
        print("")

    if args.out:
        report = {
            "events_loaded": total,
            "writes": writes,
            "reads": reads,
            "counts": {
                "cross_user_key_reuse": len(cross_user_findings),
                "cross_trace_session_key_reuse": len(cross_trace_session_findings),
                "suspicious_key_read_cross_user": len(suspicious_reads_findings),
            },
            "findings": {
                "cross_user_key_reuse": cross_user_findings,
                "cross_trace_session_key_reuse": cross_trace_session_findings,
                "suspicious_key_read_cross_user": suspicious_reads_findings,
            },
        }

        with open(args.out, "w", encoding="utf-8") as out_f:
            json.dump(report, out_f, indent=2)

        print(f"Wrote JSON report to: {args.out}")
        print("")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
