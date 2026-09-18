#!/usr/bin/env python3

from typing import Any


SUPPORTED_EVENT_TYPES = {
    "flow",
    "dns",
    "http",
    "tls",
    "alert",
}


def normalize_event(
    event_type: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise ValueError(f"Unsupported event type: {event_type}")

    if event_type == "flow":
        metadata = {
            "pkts_toserver": record.get("pkts_toserver"),
            "pkts_toclient": record.get("pkts_toclient"),
            "bytes_toserver": record.get("bytes_toserver"),
            "bytes_toclient": record.get("bytes_toclient"),
            "flow_age": record.get("flow_age"),
            "flow_state": record.get("flow_state"),
            "flow_reason": record.get("flow_reason"),
            "alerted": record.get("alerted"),
        }

    elif event_type == "dns":
        metadata = {
            "dns_type": record.get("dns_type"),
            "dns_id": record.get("dns_id"),
            "rrname": record.get("rrname"),
            "rrtype": record.get("rrtype"),
            "rcode": record.get("rcode"),
            "answers_count": record.get("answers_count"),
            "answers": record.get("answers"),
        }

    else:
        raise NotImplementedError(
            f"Normalizer not implemented yet for: {event_type}"
        )

    return {
        "event_type": event_type,
        "timestamp": record.get("timestamp"),
        "flow_id": record.get("flow_id"),
        "src_ip": record.get("src_ip"),
        "src_port": record.get("src_port"),
        "dest_ip": record.get("dest_ip"),
        "dest_port": record.get("dest_port"),
        "proto": record.get("proto"),
        "app_proto": record.get("app_proto"),
        "metadata": metadata,
    }