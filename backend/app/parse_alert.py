#!/usr/bin/env python3

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


CHECKSUM_SIGNATURE_IDS = {
    2200074,  # SURICATA TCPv4 invalid checksum
    2200075,  # SURICATA UDPv4 invalid checksum
}


def classify_noise(alert: dict[str, Any]) -> tuple[bool, str | None]:
    signature_id = alert.get("signature_id")
    signature = alert.get("signature") or ""

    if signature_id in CHECKSUM_SIGNATURE_IDS:
        return True, "invalid_checksum"

    if "invalid checksum" in signature.lower():
        return True, "invalid_checksum"

    return False, None


def normalize_alert(event: dict[str, Any]) -> dict[str, Any]:
    alert = event.get("alert") or {}
    is_noise, noise_reason = classify_noise(alert)

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "action": alert.get("action"),
        "gid": alert.get("gid"),
        "signature_id": alert.get("signature_id"),
        "rev": alert.get("rev"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "is_noise": is_noise,
        "noise_reason": noise_reason,
    }


def parse_eve_alerts(eve_path: Path) -> list[dict[str, Any]]:
    alerts = []

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

            if event.get("event_type") == "alert":
                alerts.append(normalize_alert(event))

    return alerts


def write_jsonl(alerts: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def endpoint(ip: Any, port: Any) -> str:
    if ip is None:
        return "-"

    if port is None:
        return str(ip)

    return f"{ip}:{port}"


def print_pretty_table(alerts: list[dict[str, Any]], limit: int | None = None) -> None:
    headers = [
        "SRC",
        "DEST",
        "PROTO",
        "SID",
        "SEV",
        "NOISE",
        "REASON",
        "SIGNATURE",
    ]

    if limit is not None:
        alerts = alerts[:limit]

    rows = []
    for alert in alerts:
        rows.append(
            [
                endpoint(alert.get("src_ip"), alert.get("src_port")),
                endpoint(alert.get("dest_ip"), alert.get("dest_port")),
                alert.get("proto") or "-",
                alert.get("signature_id") or "-",
                alert.get("severity") or "-",
                alert.get("is_noise"),
                alert.get("noise_reason") or "-",
                alert.get("signature") or "-",
            ]
        )

    table = [headers] + [[str(value) for value in row] for row in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(headers))]

    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))

    for row in rows:
        values = [str(value) for value in row]
        print("  ".join(values[i].ljust(widths[i]) for i in range(len(headers))))


def print_summary(alerts: list[dict[str, Any]]) -> None:
    signature_counts = Counter(alert.get("signature") or "UNKNOWN" for alert in alerts)
    severity_counts = Counter(str(alert.get("severity") or "UNKNOWN") for alert in alerts)
    category_counts = Counter(alert.get("category") or "UNKNOWN" for alert in alerts)

    noise_count = sum(1 for alert in alerts if alert.get("is_noise") is True)
    non_noise_count = len(alerts) - noise_count

    print("Alert Summary")
    print("=============")
    print(f"Total alerts: {len(alerts)}")
    print(f"Noise alerts: {noise_count}")
    print(f"Non-noise alerts: {non_noise_count}")

    print()
    print("Severity counts:")
    for severity, count in severity_counts.most_common():
        print(f"  {severity}: {count}")

    print()
    print("Category counts:")
    for category, count in category_counts.most_common():
        print(f"  {category}: {count}")

    print()
    print("Top signatures:")
    for signature, count in signature_counts.most_common(10):
        print(f"  {signature}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Suricata eve.json and normalize alert events."
    )
    parser.add_argument(
        "eve_json",
        help="Path to Suricata eve.json file",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional output path for normalized alert JSONL file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print a readable alert summary table",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print aggregate alert statistics",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit rows printed in --pretty mode",
    )

    args = parser.parse_args()
    eve_path = Path(args.eve_json)

    if not eve_path.is_file():
        raise SystemExit(f"[!] File not found: {eve_path}")

    alerts = parse_eve_alerts(eve_path)

    if args.output:
        output_path = Path(args.output)
        write_jsonl(alerts, output_path)
        print(f"[+] Wrote {len(alerts)} normalized alerts to {output_path}")

    elif args.pretty:
        print_pretty_table(alerts, limit=args.limit)
        print(f"[+] Parsed {len(alerts)} alerts from {eve_path}")

    elif args.summary:
        print_summary(alerts)

    else:
        for alert in alerts:
            print(json.dumps(alert, ensure_ascii=False))

        print(f"[+] Parsed {len(alerts)} alerts from {eve_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
