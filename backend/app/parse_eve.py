#!/usr/bin/env python3

import argparse
import json
import sys
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

    args = parser.parse_args()
    eve_path = Path(args.eve_json)

    if not eve_path.is_file():
        raise SystemExit(f"[!] File not found: {eve_path}")

    flows = parse_eve_flows(eve_path)

    if args.output:
        output_path = Path(args.output)
        write_jsonl(flows, output_path)
        print(f"[+] Wrote {len(flows)} normalized flows to {output_path}")
    else:
        for flow in flows:
            print(json.dumps(flow, ensure_ascii=False))

        print(f"[+] Parsed {len(flows)} flow events from {eve_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
