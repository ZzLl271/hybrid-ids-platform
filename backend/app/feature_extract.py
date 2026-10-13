from datetime import datetime, timezone
from collections import defaultdict
from ipaddress import ip_address

def get_window_start(flow_start: str) -> datetime:
    """Return the start of the UTC-aligned 30-second window."""

    try:
        dt = datetime.strptime(
            flow_start, "%Y-%m-%dT%H:%M:%S.%f%z"
        )
    except ValueError:
        dt = datetime.strptime(
            flow_start, "%Y-%m-%dT%H:%M:%S%z"
        )

    dt = dt.astimezone(timezone.utc)

    return dt.replace(
        second=(dt.second // 30) * 30,
        microsecond=0,
    )

def group_tcp_flows_by_window(events: list[dict]) -> dict:
    """Group normalized TCP Flow events by 30-second UTC window."""
    windows = defaultdict(list)

    for event in events:
        if event.get("event_type") != "flow":
            continue

        if str(event.get("proto", "")).upper() != "TCP":
            continue

        flow_start = (event.get("metadata") or {}).get("flow_start")

        if not flow_start:
            raise ValueError("TCP Flow missing metadata.flow_start")

        window_start = get_window_start(flow_start)
        windows[window_start].append(event)

    return dict(windows)

def count_tcp_flows_by_window(windows: dict, monitored_ip: str) -> dict:
    """Count distinct TCP flows involving the monitored host."""
    counts = {}

    for window_start, flows in windows.items():
        flow_ids = set()

        for flow in flows:
            if monitored_ip not in (
                flow.get("src_ip"),
                flow.get("dest_ip"),
            ):
                continue

            flow_id = flow.get("flow_id")
            if flow_id is None:
                raise ValueError("TCP Flow missing flow_id")

            flow_ids.add(flow_id)

        counts[window_start] = len(flow_ids)

    return counts

def count_inbound_tcp_flows_by_window(
    windows: dict, monitored_ip: str
) -> dict:
    """Count distinct inbound TCP flows per window."""
    counts = {}

    for window_start, flows in windows.items():
        flow_ids = set()

        for flow in flows:
            if flow.get("dest_ip") != monitored_ip:
                continue

            if flow.get("src_ip") == monitored_ip:
                continue

            flow_id = flow.get("flow_id")
            if flow_id is None:
                raise ValueError("Inbound TCP Flow missing flow_id")

            flow_ids.add(flow_id)

        counts[window_start] = len(flow_ids)

    return counts

def count_outbound_tcp_flows_by_window(
    windows: dict, monitored_ip: str
) -> dict:
    """Count distinct outbound TCP flows per window."""
    counts = {}

    for window_start, flows in windows.items():
        flow_ids = set()

        for flow in flows:
            if flow.get("src_ip") != monitored_ip:
                continue

            if flow.get("dest_ip") == monitored_ip:
                continue

            flow_id = flow.get("flow_id")
            if flow_id is None:
                raise ValueError("Outbound TCP Flow missing flow_id")

            flow_ids.add(flow_id)

        counts[window_start] = len(flow_ids)

    return counts

def count_inbound_unique_dest_ports_by_window(
    windows: dict, monitored_ip: str
) -> dict:
    """Count unique TCP destination ports targeted by inbound flows."""
    counts = {}

    for window_start, flows in windows.items():
        dest_ports = set()

        for flow in flows:
            if flow.get("dest_ip") != monitored_ip:
                continue

            src_ip = flow.get("src_ip")
            if not src_ip or src_ip == monitored_ip:
                continue

            port = flow.get("dest_port")

            if (
                isinstance(port, int)
                and not isinstance(port, bool)
                and 1 <= port <= 65535
            ):
                dest_ports.add(port)

        counts[window_start] = len(dest_ports)

    return counts

def count_outbound_unique_dest_ips_by_window(
    windows: dict, monitored_ip: str
) -> dict:
    """Count unique destination IPs of outbound TCP flows."""
    counts = {}

    for window_start, flows in windows.items():
        dest_ips = set()

        for flow in flows:
            if flow.get("src_ip") != monitored_ip:
                continue

            dest_ip = flow.get("dest_ip")

            if not isinstance(dest_ip, str) or dest_ip == monitored_ip:
                continue

            try:
                dest_ips.add(ip_address(dest_ip))
            except ValueError:
                continue

        counts[window_start] = len(dest_ips)

    return counts

def count_inbound_max_unique_ports_by_window(
    windows: dict, monitored_ip: str
) -> dict:
    """Maximum unique destination ports accessed by one inbound source."""
    counts = {}

    for window_start, flows in windows.items():
        ports_by_source = {}

        for flow in flows:
            if flow.get("dest_ip") != monitored_ip:
                continue

            src_ip = flow.get("src_ip")
            if not src_ip or src_ip == monitored_ip:
                continue

            try:
                src_ip = str(ip_address(src_ip))
            except ValueError:
                continue

            port = flow.get("dest_port")
            if (
                not isinstance(port, int)
                or isinstance(port, bool)
                or not 1 <= port <= 65535
            ):
                continue

            ports_by_source.setdefault(src_ip, set()).add(port)

        counts[window_start] = max(
            (len(ports) for ports in ports_by_source.values()),
            default=0,
        )

    return counts

def build_feature_rows(windows: dict, monitored_ip: str) -> list[dict]:
    """Combine six TCP features into one row per time window."""

    features = {
        "tcp_flow_count":
            count_tcp_flows_by_window(windows, monitored_ip),

        "tcp_inbound_flow_count":
            count_inbound_tcp_flows_by_window(windows, monitored_ip),

        "tcp_outbound_flow_count":
            count_outbound_tcp_flows_by_window(windows, monitored_ip),

        "tcp_inbound_unique_dest_port_count":
            count_inbound_unique_dest_ports_by_window(windows, monitored_ip),

        "tcp_outbound_unique_dest_ip_count":
            count_outbound_unique_dest_ips_by_window(windows, monitored_ip),

        "tcp_inbound_max_unique_dest_ports_per_src_ip":
            count_inbound_max_unique_ports_by_window(windows, monitored_ip),
    }

    rows = []

    for window_start in sorted(windows):
        row = {
            "window_start": window_start.isoformat(),
            "monitored_ip": monitored_ip,
        }

        for feature_name, counts in features.items():
            row[feature_name] = counts[window_start]

        rows.append(row)

    return rows

def save_feature_rows_csv(rows: list[dict], output_path: str) -> None:
    """Save feature rows to a CSV file."""
    import csv
    from pathlib import Path

    if not rows:
        raise ValueError("No feature rows to save")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)