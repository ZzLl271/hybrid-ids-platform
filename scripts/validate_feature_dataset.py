import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from backend.app.feature_extract import FEATURE_DATASET_FIELDS


WINDOW_SECONDS = 30
FEATURE_FIELDS = FEATURE_DATASET_FIELDS[2:]

CONSISTENCY_RULES = (
    ("tcp_inbound_unique_dest_port_count",
     "tcp_inbound_flow_count"),
    ("tcp_inbound_max_unique_dest_ports_per_src_ip",
     "tcp_inbound_unique_dest_port_count"),
    ("tcp_inbound_unique_src_ip_count",
     "tcp_inbound_flow_count"),
    ("tcp_outbound_unique_dest_ip_count",
     "tcp_outbound_flow_count"),
    ("tcp_outbound_unique_dest_port_count",
     "tcp_outbound_flow_count"),
    ("tcp_outbound_max_unique_dest_ips_per_dest_port",
     "tcp_outbound_unique_dest_ip_count"),
)

"""Check CSV structure and consistency; return 0 on success, otherwise 1.
PASS does not establish capture completeness or correct attack labels.
Window gaps are informational and do not establish zero traffic.
"""
def validate_dataset(path: Path) -> int:
    errors = []
    windows_by_host = defaultdict(list)
    seen = set()
    row_count = 0

    try:
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames != list(FEATURE_DATASET_FIELDS):
                print("FAIL: CSV schema mismatch")
                print("Expected:", list(FEATURE_DATASET_FIELDS))
                print("Actual:  ", reader.fieldnames)
                return 1

            for line_number, row in enumerate(reader, start=2):
                row_count += 1

                if None in row:
                    errors.append(
                        f"Line {line_number}: unexpected extra values"
                    )
                    continue

                host = row["monitored_ip"]

                try:
                    ip_address(host)
                except (ValueError, TypeError):
                    errors.append(
                        f"Line {line_number}: invalid monitored_ip"
                    )
                    continue

                try:
                    window = datetime.fromisoformat(
                        row["window_start"]
                    )

                    if (
                        window.utcoffset() != timedelta(0)
                        or window.second not in (0, 30)
                        or window.microsecond != 0
                    ):
                        raise ValueError

                except (ValueError, TypeError, AttributeError):
                    errors.append(
                        f"Line {line_number}: invalid UTC window"
                    )
                    continue

                key = (host, window)

                if key in seen:
                    errors.append(
                        f"Line {line_number}: duplicate host/window"
                    )

                seen.add(key)
                windows_by_host[host].append(window)

                values = {}

                for field in FEATURE_FIELDS:
                    raw = row[field]

                    if (
                        not isinstance(raw, str)
                        or not raw.isascii()
                        or not raw.isdecimal()
                    ):
                        errors.append(
                            f"Line {line_number}: invalid {field}"
                        )
                        continue

                    values[field] = int(raw)

                if len(values) != len(FEATURE_FIELDS):
                    continue

                for smaller, larger in CONSISTENCY_RULES:
                    if values[smaller] > values[larger]:
                        errors.append(
                            f"Line {line_number}: "
                            f"{smaller} exceeds {larger}"
                        )

    except (OSError, UnicodeError, csv.Error) as error:
        print(f"FAIL: cannot read CSV: {error}")
        return 1

    if row_count == 0:
        errors.append("Dataset contains no feature rows")

    for host, windows in windows_by_host.items():
        if windows != sorted(windows):
            errors.append(
                f"Host {host}: windows are not sorted"
            )

    print(f"Dataset: {path}")
    print(f"Rows checked: {row_count}")
    print(f"Hosts: {len(windows_by_host)}")

    if errors:
        print(f"Validation: FAIL ({len(errors)} errors)")

        for error in errors[:20]:
            print(" -", error)

        return 1

    total_gaps = 0

    for host, windows in sorted(windows_by_host.items()):
        ordered = sorted(set(windows))
        gaps = 0

        for previous, current in zip(
            ordered, ordered[1:]
        ):
            difference = int(
                (current - previous).total_seconds()
            )

            gaps += max(
                0, difference // WINDOW_SECONDS - 1
            )

        total_gaps += gaps

        print(f"\nHost: {host}")
        print(f"Observed windows: {len(ordered)}")
        print(f"Gaps between observed windows: {gaps}")

    print("\nValidation: PASS")
    print(f"Total observed window gaps: {total_gaps}")
    print(
        "Note: gaps are informational; "
        "capture completeness is not verified."
    )

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a TCP v1 feature dataset CSV"
    )

    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    sys.exit(validate_dataset(Path(args.input)))


if __name__ == "__main__":
    main()