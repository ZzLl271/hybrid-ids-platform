#!/usr/bin/env python3

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def normalize_tls(event: dict[str, Any]) -> dict[str, Any]:
    tls = event.get("tls") or {}
    ja3 = tls.get("ja3") or {}
    ja3s = tls.get("ja3s") or {}

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "sni": tls.get("sni"),
        "tls_version": tls.get("version"),
        "subject": tls.get("subject"),
        "issuerdn": tls.get("issuerdn"),
        "fingerprint": tls.get("fingerprint"),
        "ja3_hash": ja3.get("hash"),
        "ja3_string": ja3.get("string"),
        "ja3s_hash": ja3s.get("hash"),
        "ja3s_string": ja3s.get("string"),
    }


def parse_eve_tls(eve_path: Path) -> list[dict[str, Any]]:
    tls_events = []

    with eve_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                print(
                    f"[!] Skipping invalid JSON on line {line_number}: {error}",
                    file=sys.stderr,
                )
                continue

            if event.get("event_type") == "tls":
                tls_events.append(normalize_tls(event))

    return tls_events


def write_jsonl(events: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def endpoint(ip: Any, port: Any) -> str:
    if ip is None:
        return "-"

    if port is None:
        return str(ip)

    return f"{ip}:{port}"


def short_hash(value: Any) -> str:
    if not value:
        return "-"

    value = str(value)
    return value[:12]


def print_pretty_table(events: list[dict[str, Any]]) -> None:
    headers = [
        "SRC",
        "DEST",
        "SNI",
        "TLS",
        "JA3",
        "JA3S",
    ]

    rows = []
    for event in events:
        rows.append(
            [
                endpoint(event.get("src_ip"), event.get("src_port")),
                endpoint(event.get("dest_ip"), event.get("dest_port")),
                event.get("sni") or "-",
                event.get("tls_version") or "-",
                short_hash(event.get("ja3_hash")),
                short_hash(event.get("ja3s_hash")),
            ]
        )

    table = [headers] + [[str(value) for value in row] for row in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(headers))]

    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))

    for row in rows:
        values = [str(value) for value in row]
        print("  ".join(values[i].ljust(widths[i]) for i in range(len(headers))))


def print_summary(events: list[dict[str, Any]]) -> None:
    sni_counts = Counter(event.get("sni") or "UNKNOWN" for event in events)
    version_counts = Counter(event.get("tls_version") or "UNKNOWN" for event in events)
    ja3_counts = Counter(event.get("ja3_hash") or "UNKNOWN" for event in events)
    ja3s_counts = Counter(event.get("ja3s_hash") or "UNKNOWN" for event in events)

    print("TLS Summary")
    print("===========")
    print(f"Total TLS events: {len(events)}")

    print()
    print("TLS version counts:")
    for version, count in version_counts.most_common():
        print(f"  {version}: {count}")

    print()
    print("Top SNI values:")
    for sni, count in sni_counts.most_common(10):
        print(f"  {sni}: {count}")

    print()
    print("Top JA3 hashes:")
    for ja3_hash, count in ja3_counts.most_common(10):
        print(f"  {ja3_hash}: {count}")

    print()
    print("Top JA3S hashes:")
    for ja3s_hash, count in ja3s_counts.most_common(10):
        print(f"  {ja3s_hash}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Suricata eve.json and normalize TLS events."
    )
    parser.add_argument(
        "eve_json",
        help="Path to Suricata eve.json file",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional output path for normalized TLS JSONL file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print a readable TLS summary table",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print aggregate TLS statistics",
    )

    args = parser.parse_args()
    eve_path = Path(args.eve_json)

    if not eve_path.is_file():
        raise SystemExit(f"[!] File not found: {eve_path}")

    events = parse_eve_tls(eve_path)

    if args.output:
        output_path = Path(args.output)
        write_jsonl(events, output_path)
        print(f"[+] Wrote {len(events)} normalized TLS events to {output_path}")

    elif args.pretty:
        print_pretty_table(events)
        print(f"[+] Parsed {len(events)} TLS events from {eve_path}")

    elif args.summary:
        print_summary(events)

    else:
        for event in events:
            print(json.dumps(event, ensure_ascii=False))

        print(f"[+] Parsed {len(events)} TLS events from {eve_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
