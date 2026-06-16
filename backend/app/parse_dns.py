#!/usr/bin/env python3

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def normalize_answer(answer: dict[str, Any]) -> dict[str, Any]:
    return {
        "rrname": answer.get("rrname"),
        "rrtype": answer.get("rrtype"),
        "rdata": answer.get("rdata"),
    }


def normalize_dns(event: dict[str, Any]) -> dict[str, Any]:
    dns = event.get("dns") or {}
    answers = dns.get("answers") or []

    return {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "dns_type": dns.get("type"),
        "dns_id": dns.get("id"),
        "rrname": dns.get("rrname"),
        "rrtype": dns.get("rrtype"),
        "rcode": dns.get("rcode"),
        "answers_count": len(answers),
        "answers": [normalize_answer(answer) for answer in answers],
    }


def parse_eve_dns(eve_path: Path) -> list[dict[str, Any]]:
    dns_events = []

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

            if event.get("event_type") == "dns":
                dns_events.append(normalize_dns(event))

    return dns_events


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
        "TYPE",
        "RRNAME",
        "RRTYPE",
        "RCODE",
        "ANSWERS",
    ]

    rows = []
    for event in events:
        rows.append(
            [
                endpoint(event.get("src_ip"), event.get("src_port")),
                endpoint(event.get("dest_ip"), event.get("dest_port")),
                event.get("dns_type") or "-",
                event.get("rrname") or "-",
                event.get("rrtype") or "-",
                event.get("rcode") or "-",
                event.get("answers_count"),
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
    domain_counts = Counter(event.get("rrname") or "UNKNOWN" for event in events)
    type_counts = Counter(event.get("dns_type") or "UNKNOWN" for event in events)
    rrtype_counts = Counter(event.get("rrtype") or "UNKNOWN" for event in events)

    print("DNS Summary")
    print("===========")
    print(f"Total DNS events: {len(events)}")

    print()
    print("DNS type counts:")
    for dns_type, count in type_counts.most_common():
        print(f"  {dns_type}: {count}")

    print()
    print("RR type counts:")
    for rrtype, count in rrtype_counts.most_common():
        print(f"  {rrtype}: {count}")

    print()
    print("Top domains:")
    for domain, count in domain_counts.most_common(10):
        print(f"  {domain}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Suricata eve.json and normalize DNS events."
    )
    parser.add_argument(
        "eve_json",
        help="Path to Suricata eve.json file",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional output path for normalized DNS JSONL file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print a readable DNS summary table",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print aggregate DNS statistics",
    )

    args = parser.parse_args()
    eve_path = Path(args.eve_json)

    if not eve_path.is_file():
        raise SystemExit(f"[!] File not found: {eve_path}")

    events = parse_eve_dns(eve_path)

    if args.output:
        output_path = Path(args.output)
        write_jsonl(events, output_path)
        print(f"[+] Wrote {len(events)} normalized DNS events to {output_path}")

    elif args.pretty:
        print_pretty_table(events)
        print(f"[+] Parsed {len(events)} DNS events from {eve_path}")

    elif args.summary:
        print_summary(events)

    else:
        for event in events:
            print(json.dumps(event, ensure_ascii=False))

        print(f"[+] Parsed {len(events)} DNS events from {eve_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
