#!/usr/bin/env python3

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def normalize_flow(event: dict[str, Any]) -> dict[str, Any]:
    flow = event.get("flow") or {}

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
        "pkts_toserver": flow.get("pkts_toserver", 0),
        "pkts_toclient": flow.get("pkts_toclient", 0),
        "bytes_toserver": flow.get("bytes_toserver", 0),
        "bytes_toclient": flow.get("bytes_toclient", 0),
        "flow_age": flow.get("age"),
        "flow_state": flow.get("state"),
        "flow_reason": flow.get("reason"),
        "alerted": flow.get("alerted", False),
    }


def parse_eve_flows(eve_path: Path) -> list[dict[str, Any]]:
    flows = []

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

            if event.get("event_type") == "flow":
                flows.append(normalize_flow(event))

    return flows


def write_jsonl(flows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for flow in flows:
            f.write(json.dumps(flow, ensure_ascii=False) + "\n")


def endpoint(ip: Any, port: Any) -> str:
    if ip is None:
        return "-"

    if port is None:
        return str(ip)

    return f"{ip}:{port}"


def print_pretty_table(flows: list[dict[str, Any]]) -> None:
    headers = [
        "SRC",
        "DEST",
        "PROTO",
        "APP",
        "PKTS_TS",
        "PKTS_TC",
        "BYTES_TS",
        "BYTES_TC",
        "STATE",
        "ALERTED",
    ]

    rows = []
    for flow in flows:
        rows.append(
            [
                endpoint(flow.get("src_ip"), flow.get("src_port")),
                endpoint(flow.get("dest_ip"), flow.get("dest_port")),
                flow.get("proto") or "-",
                flow.get("app_proto") or "-",
                flow.get("pkts_toserver"),
                flow.get("pkts_toclient"),
                flow.get("bytes_toserver"),
                flow.get("bytes_toclient"),
                flow.get("flow_state") or "-",
                flow.get("alerted"),
            ]
        )

    table = [headers] + [[str(value) for value in row] for row in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(headers))]

    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))

    for row in rows:
        values = [str(value) for value in row]
        print("  ".join(values[i].ljust(widths[i]) for i in range(len(headers))))


def print_summary(flows: list[dict[str, Any]]) -> None:
    proto_counts = Counter(flow.get("proto") or "UNKNOWN" for flow in flows)
    alerted_count = sum(1 for flow in flows if flow.get("alerted") is True)

    total_bytes_toserver = sum(flow.get("bytes_toserver") or 0 for flow in flows)
    total_bytes_toclient = sum(flow.get("bytes_toclient") or 0 for flow in flows)
    total_bytes = total_bytes_toserver + total_bytes_toclient

    print("Flow Summary")
    print("============")
    print(f"Total flows: {len(flows)}")
    print(f"Alerted flows: {alerted_count}")
    print(f"Total bytes: {total_bytes}")
    print(f"Bytes to server: {total_bytes_toserver}")
    print(f"Bytes to client: {total_bytes_toclient}")

    print()
    print("Protocol counts:")
    for proto, count in proto_counts.most_common():
        print(f"  {proto}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Suricata eve.json and normalize flow events."
    )
    parser.add_argument(
        "eve_json",
        help="Path to Suricata eve.json file",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional output path for normalized flow JSONL file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print a readable flow summary table",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print aggregate flow statistics",
    )

    args = parser.parse_args()
    eve_path = Path(args.eve_json)

    if not eve_path.is_file():
        raise SystemExit(f"[!] File not found: {eve_path}")

    flows = parse_eve_flows(eve_path)

    if args.output:
        output_path = Path(args.output)
        write_jsonl(flows, output_path)
        print(f"[+] Wrote {len(flows)} normalized flows to {output_path}")

    elif args.pretty:
        print_pretty_table(flows)
        print(f"[+] Parsed {len(flows)} flow events from {eve_path}")

    elif args.summary:
        print_summary(flows)

    else:
        for flow in flows:
            print(json.dumps(flow, ensure_ascii=False))

        print(f"[+] Parsed {len(flows)} flow events from {eve_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
