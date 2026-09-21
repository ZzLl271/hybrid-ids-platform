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
    elif event_type == "http":
        metadata = {
            "hostname": record.get("hostname"),
            "url": record.get("url"),
            "http_method": record.get("http_method"),
            "protocol": record.get("protocol"),
            "status": record.get("status"),
            "http_user_agent": record.get("http_user_agent"),
            "http_content_type": record.get("http_content_type"),
            "length": record.get("length"),
        }
    elif event_type == "tls":
        metadata = {
            "sni": record.get("sni"),
            "tls_version": record.get("tls_version"),
            "subject": record.get("subject"),
            "issuerdn": record.get("issuerdn"),
            "fingerprint": record.get("fingerprint"),
            "ja3_hash": record.get("ja3_hash"),
            "ja3_string": record.get("ja3_string"),
            "ja3s_hash": record.get("ja3s_hash"),
            "ja3s_string": record.get("ja3s_string"),
        }
    elif event_type == "alert":
        metadata = {
            "action": record.get("action"),
            "gid": record.get("gid"),
            "signature_id": record.get("signature_id"),
            "rev": record.get("rev"),
            "signature": record.get("signature"),
            "category": record.get("category"),
            "severity": record.get("severity"),
            "is_noise": record.get("is_noise"),
            "noise_reason": record.get("noise_reason"),
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