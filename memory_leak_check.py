import argparse
import json


def main() -> int:
    ap = argparse.ArgumentParser(description="Agent Memory Leak Checker (MVP)")
    ap.add_argument("--log", required=True, help="Path to JSONL memory log file")
    args = ap.parse_args()

    events = 0
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

            events += 1
            ev = obj.get("event")
            if ev == "memory_read":
                reads += 1
            elif ev == "memory_write":
                writes += 1

    print("")
    print("Agent Memory Leak Checker (MVP)")
    print(f"Events loaded: {events}")
    print(f"Writes: {writes}")
    print(f"Reads: {reads}")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
