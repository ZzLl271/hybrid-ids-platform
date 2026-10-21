import argparse
from ipaddress import ip_address
from pathlib import Path

from backend.app.parse_eve import parse_eve_flows
from backend.app.normalize_event import normalize_event
from backend.app.feature_extract import (
    group_tcp_flows_by_window,
    build_feature_rows,
    save_feature_rows_csv,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a v1 TCP feature CSV from Suricata EVE JSONL"
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--monitored-ip", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        ip_address(args.monitored_ip)
    except ValueError:
        parser.error("--monitored-ip must be a valid IP address")

    input_path = Path(args.input)
    if not input_path.is_file():
        parser.error(f"Input file not found: {input_path}")

    try:
        parsed_flows = parse_eve_flows(input_path, strict=True)
    except ValueError as error:
        parser.error(str(error))

# Keep flows with exactly one endpoint equal to the monitored host.
# Exclude unrelated flows and self-to-self records.
    monitored_flows = [
        normalize_event("flow", flow)
        for flow in parsed_flows
        if str(flow.get("proto", "")).upper() == "TCP"
        and (
            (flow.get("src_ip") == args.monitored_ip)
            != (flow.get("dest_ip") == args.monitored_ip)
        )
    ]

    if not monitored_flows:
        parser.error("No TCP flows involving the monitored host were found")

    try:
        windows = group_tcp_flows_by_window(monitored_flows)
        rows = build_feature_rows(windows, args.monitored_ip)
        save_feature_rows_csv(rows, args.output)
    except ValueError as error:
        parser.error(str(error))

    print(f"Wrote {len(rows)} feature rows to {args.output}")
    print(
        "Note: these are observed-flow windows, "
        "not verified-complete capture windows."
    )


if __name__ == "__main__":
    main()