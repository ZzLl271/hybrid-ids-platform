#!/usr/bin/env python3

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def normalize_http(event: dict[str, Any]) -> dict[str, Any]:
    http = event.get("http") or {}

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "hostname": http.get("hostname"),
        "url": http.get("url"),
        "http_method": http.get("http_method"),
        "protocol": http.get("protocol"),
        "status": http.get("status"),
        "http_user_agent": http.get("http_user_agent"),
        "http_content_type": http.get("http_content_type"),
        "length": http.get("length"),
    }


def parse_eve_http(eve_path: Path) -> list[dict[str, Any]]:
    http_events = []

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

            if event.get("event_type") == "http":
                http_events.append(normalize_http(event))

    return http_events


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


def print_pretty_table(events: list[dict[str, Any]]) -> None:
    headers = [
        "SRC",
        "DEST",
        "HOST",
        "METHOD",
        "URL",
        "STATUS",
        "UA",
    ]

    rows = []
    for event in events:
        rows.append(
            [
                endpoint(event.get("src_ip"), event.get("src_port")),
                endpoint(event.get("dest_ip"), event.get("dest_port")),
                event.get("hostname") or "-",
                event.get("http_method") or "-",
                event.get("url") or "-",
                event.get("status") or "-",
                event.get("http_user_agent") or "-",
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
    host_counts = Counter(event.get("hostname") or "UNKNOWN" for event in events)
    method_counts = Counter(event.get("http_method") or "UNKNOWN" for event in events)
    status_counts = Counter(str(event.get("status") or "UNKNOWN") for event in events)

    print("HTTP Summary")
    print("============")
    print(f"Total HTTP events: {len(events)}")

    print()
    print("Method counts:")
    for method, count in method_counts.most_common():
        print(f"  {method}: {count}")

    print()
    print("Status counts:")
    for status, count in status_counts.most_common():
        print(f"  {status}: {count}")

    print()
    print("Top hosts:")
    for host, count in host_counts.most_common(10):
        print(f"  {host}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Suricata eve.json and normalize HTTP events."
    )
    parser.add_argument(
        "eve_json",
        help="Path to Suricata eve.json file",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional output path for normalized HTTP JSONL file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print a readable HTTP summary table",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print aggregate HTTP statistics",
    )

    args = parser.parse_args()
    eve_path = Path(args.eve_json)

    if not eve_path.is_file():
        raise SystemExit(f"[!] File not found: {eve_path}")

    events = parse_eve_http(eve_path)

    if args.output:
        output_path = Path(args.output)
        write_jsonl(events, output_path)
        print(f"[+] Wrote {len(events)} normalized HTTP events to {output_path}")

    elif args.pretty:
        print_pretty_table(events)
        print(f"[+] Parsed {len(events)} HTTP events from {eve_path}")

    elif args.summary:
        print_summary(events)

    else:
        for event in events:
            print(json.dumps(event, ensure_ascii=False))

        print(f"[+] Parsed {len(events)} HTTP events from {eve_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
