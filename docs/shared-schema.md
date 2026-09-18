# Shared Normalized Event Schema

## Structure

Example DNS record:

```json
{
  "event_type": "dns",
  "timestamp": "2026-06-16T00:00:01.100000+0000",
  "flow_id": null,
  "src_ip": "192.0.2.10",
  "src_port": 51505,
  "dest_ip": "198.51.100.53",
  "dest_port": 53,
  "proto": "UDP",
  "app_proto": null,
  "metadata": {
    "dns_type": "query",
    "dns_id": 12345,
    "rrname": "example.com",
    "rrtype": "A",
    "rcode": null,
    "answers_count": 0,
    "answers": []
  }
}
```

## Core fields

| Field | Type | Nullable | Notes |
|---|---|---:|---|
| `event_type` | string | No | `flow`, `dns`, `http`, `tls`, `alert` |
| `timestamp` | string | Yes | Keep parser value as-is |
| `flow_id` | integer | Yes | Use parser-provided value; otherwise `null` |
| `src_ip` | string | Yes | Source IP |
| `src_port` | integer | Yes | Source port |
| `dest_ip` | string | Yes | Destination IP |
| `dest_port` | integer | Yes | Destination port |
| `proto` | string | Yes | Transport protocol |
| `app_proto` | string | Yes | Use parser-provided value; otherwise `null` |
| `metadata` | object | No | Event-specific fields |

`event_type` is supplied by parser context. Do not infer it from record fields.

## Missing values

Core fields:

```text
missing scalar -> null
missing object -> {}
```

Metadata keeps the values already produced by the current event-specific parser.

Do not replace parser defaults such as `0`, `false`, or `[]` with `null`.

The unified normalizer does not recover whether a parser default came from a missing raw field.

This contract describes the current normalized output shape. The unified normalizer restructures parser output and does not add a separate validation or coercion layer.

## Metadata

### Flow

| Field | Type | Nullable | Parser behavior | Meaning |
|---|---|---:|---|---|
| `pkts_toserver` | integer | Yes | Missing key -> `0`; explicit `null` remains `null` | Packets to server |
| `pkts_toclient` | integer | Yes | Missing key -> `0`; explicit `null` remains `null` | Packets to client |
| `bytes_toserver` | integer | Yes | Missing key -> `0`; explicit `null` remains `null` | Bytes to server |
| `bytes_toclient` | integer | Yes | Missing key -> `0`; explicit `null` remains `null` | Bytes to client |
| `flow_age` | integer | Yes | Missing key -> `null` | Flow duration in seconds |
| `flow_state` | string | Yes | Missing key -> `null` | Flow state |
| `flow_reason` | string | Yes | Missing key -> `null` | Reason the flow ended |
| `alerted` | boolean | Yes | Missing key -> `false`; explicit `null` remains `null` | Whether the flow generated an alert |

### DNS

| Field | Type | Nullable | Default / Rule |
|---|---|---:|---|
| `dns_type` | string | Yes | `null` |
| `dns_id` | integer | Yes | `null` |
| `rrname` | string | Yes | `null` |
| `rrtype` | string | Yes | `null` |
| `rcode` | string | Yes | `null` |
| `answers_count` | integer | No | `len(answers)` |
| `answers` | array | No | Missing or null input -> `[]` |

Each `answers` item:

| Field | Type | Nullable |
|---|---|---:|
| `rrname` | string | Yes |
| `rrtype` | string | Yes |
| `rdata` | string | Yes |

Rule:

```text
answers_count == len(answers)
```

### HTTP

| Field | Type | Nullable | Meaning |
|---|---|---:|---|
| `hostname` | string | Yes | HTTP hostname |
| `url` | string | Yes | Request URL/path |
| `http_method` | string | Yes | HTTP method |
| `protocol` | string | Yes | HTTP protocol/version |
| `status` | integer | Yes | HTTP status code |
| `http_user_agent` | string | Yes | User-Agent value |
| `http_content_type` | string | Yes | Content-Type value |
| `length` | integer | Yes | HTTP body content size in bytes |

```text
proto    = transport protocol
protocol = HTTP protocol/version
```

### TLS

| Field | Type | Nullable |
|---|---|---:|
| `sni` | string | Yes |
| `tls_version` | string | Yes |
| `subject` | string | Yes |
| `issuerdn` | string | Yes |
| `fingerprint` | string | Yes |
| `ja3_hash` | string | Yes |
| `ja3_string` | string | Yes |
| `ja3s_hash` | string | Yes |
| `ja3s_string` | string | Yes |

JA3 and JA3S remain flattened as produced by the current TLS parser.

### Alert

| Field | Type | Nullable | Rule |
|---|---|---:|---|
| `action` | string | Yes | Parser value |
| `gid` | integer | Yes | Parser value |
| `signature_id` | integer | Yes | Parser value |
| `rev` | integer | Yes | Parser value |
| `signature` | string | Yes | Parser value |
| `category` | string | Yes | Parser value |
| `severity` | integer | Yes | Parser value |
| `is_noise` | boolean | No | Derived by alert parser |
| `noise_reason` | string | Yes | Derived by alert parser |

Current noise rule:

```text
signature_id = 2200074 or 2200075
or signature contains "invalid checksum" (case-insensitive)
-> is_noise = true
-> noise_reason = "invalid_checksum"

otherwise
-> is_noise = false
-> noise_reason = null
```

## Rules

- Same top-level keys for all events.
- Event-specific fields go inside `metadata`.
- Each event type keeps a fixed set of metadata keys.
- `event_type` determines which metadata contract applies.
- `event_type` is supplied by parser context.
- `flow_id` uses the parser-provided value; otherwise `null`.
- `app_proto` uses the parser-provided value; otherwise `null`.
- Keep the current parser timestamp value as-is.
- Do not infer missing values.
- Keep existing parser defaults for event-specific fields.
- Do not coerce explicit parser `null` values into defaults.
- The normalizer does not recover whether a parser default came from a missing raw field.