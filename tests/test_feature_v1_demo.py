import copy
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from backend.app.normalize_event import normalize_event
from backend.app.feature_extract import (
    group_tcp_flows_by_window,
    build_feature_rows,
    save_feature_rows_csv,
)

SAMPLE = "samples/eve-demo.json"
HOST = "192.0.2.10"

EXPECTED = {
    "tcp_inbound_flow_count": 3,
    "tcp_outbound_flow_count": 3,
    "tcp_inbound_unique_dest_port_count": 3,
    "tcp_inbound_max_unique_dest_ports_per_src_ip": 2,
    "tcp_inbound_unique_src_ip_count": 2,
    "tcp_outbound_unique_dest_ip_count": 3,
    "tcp_outbound_unique_dest_port_count": 2,
    "tcp_outbound_max_unique_dest_ips_per_dest_port": 2,
}


class TestFeatureV1Demo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [sys.executable, "backend/app/parse_eve.py", SAMPLE],
            capture_output=True,
            text=True,
            check=True,
        )

        parsed = [
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        assert len(parsed) == 7

        cls.events = [
            normalize_event("flow", record)
            for record in parsed
        ]

    def test_end_to_end_and_csv(self):
        windows = group_tcp_flows_by_window(self.events)
        rows = build_feature_rows(windows, HOST)

        self.assertEqual(len(windows), 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["window_start"],
            "2026-06-16T00:00:00+00:00",
        )
        self.assertEqual(rows[0]["monitored_ip"], HOST)
        self.assertEqual(
            set(rows[0]),
            {"window_start", "monitored_ip", *EXPECTED},
        )

        for name, value in EXPECTED.items():
            self.assertEqual(rows[0][name], value)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "features.csv"
            save_feature_rows_csv(rows, str(path))

            with path.open(newline="", encoding="utf-8") as f:
                saved = list(csv.DictReader(f))

            self.assertEqual(len(saved), 1)

            for name, value in EXPECTED.items():
                self.assertEqual(int(saved[0][name]), value)

    def test_missing_required_fields(self):
        tcp = [
            event for event in self.events
            if event["proto"] == "TCP"
        ]

        missing_start = copy.deepcopy(tcp[0])
        missing_start["metadata"].pop("flow_start", None)

        with self.assertRaises(ValueError):
            group_tcp_flows_by_window([missing_start])

        missing_id = copy.deepcopy(tcp[0])
        missing_id["flow_id"] = None

        windows = group_tcp_flows_by_window([missing_id])

        with self.assertRaises(ValueError):
            build_feature_rows(windows, HOST)

    def test_invalid_inbound_ports(self):
        events = copy.deepcopy(self.events)

        for event in events:
            if (
                event["proto"] == "TCP"
                and event["dest_ip"] == HOST
            ):
                event["dest_port"] = 0

        windows = group_tcp_flows_by_window(events)
        row = build_feature_rows(windows, HOST)[0]

        self.assertEqual(row["tcp_inbound_flow_count"], 3)
        self.assertEqual(
            row["tcp_inbound_unique_dest_port_count"], 0
        )
        self.assertEqual(
            row["tcp_inbound_max_unique_dest_ports_per_src_ip"], 0
        )


if __name__ == "__main__":
    unittest.main()
