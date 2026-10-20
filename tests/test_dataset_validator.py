import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from backend.app.feature_extract import FEATURE_DATASET_FIELDS


ROOT = Path(__file__).resolve().parents[1]
FIELDS = list(FEATURE_DATASET_FIELDS)


class TestDatasetValidator(unittest.TestCase):

    def make_row(self, **changes):
        row = {
            field: "0"
            for field in FIELDS[2:]
        }

        row.update({
            "window_start": "2017-07-03T13:00:00+00:00",
            "monitored_ip": "192.168.10.50",
            "tcp_inbound_flow_count": "3",
            "tcp_outbound_flow_count": "2",
            "tcp_inbound_unique_dest_port_count": "2",
            "tcp_inbound_max_unique_dest_ports_per_src_ip": "2",
            "tcp_inbound_unique_src_ip_count": "2",
            "tcp_outbound_unique_dest_ip_count": "2",
            "tcp_outbound_unique_dest_port_count": "1",
            "tcp_outbound_max_unique_dest_ips_per_dest_port": "2",
        })

        row.update(changes)
        return row

    def run_validator(self, rows, fields=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "features.csv"

            with path.open(
                "w", newline="", encoding="utf-8"
            ) as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=fields or FIELDS,
                    extrasaction="ignore",
                )
                writer.writeheader()
                writer.writerows(rows)

            return subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "scripts.validate_feature_dataset",
                    "--input",
                    str(path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

    def test_valid_dataset_passes(self):
        result = self.run_validator([
            self.make_row()
        ])

        self.assertEqual(result.returncode, 0)
        self.assertIn("Validation: PASS", result.stdout)

    def test_observed_gap_is_informational(self):
        result = self.run_validator([
            self.make_row(),
            self.make_row(
                window_start="2017-07-03T13:01:00+00:00"
            ),
        ])

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "Total observed window gaps: 1",
            result.stdout,
        )

    def test_schema_mismatch_fails(self):
        result = self.run_validator(
            [self.make_row()],
            fields=FIELDS[:-1],
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema mismatch", result.stdout)

    def test_empty_dataset_fails(self):
        result = self.run_validator([])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Validation: FAIL", result.stdout)

    def test_invalid_monitored_ip_fails(self):
        result = self.run_validator([
            self.make_row(monitored_ip="invalid-ip")
        ])

        self.assertNotEqual(result.returncode, 0)

    def test_invalid_feature_values_fail(self):
        for value in ("-1", "", "abc"):
            with self.subTest(value=value):
                result = self.run_validator([
                    self.make_row(
                        tcp_inbound_flow_count=value
                    )
                ])

                self.assertNotEqual(result.returncode, 0)

    def test_invalid_window_times_fail(self):
        invalid_times = (
            "2017-07-03T13:00:00-04:00",
            "2017-07-03T13:00:15+00:00",
            "2017-07-03T13:00:00",
        )

        for timestamp in invalid_times:
            with self.subTest(timestamp=timestamp):
                result = self.run_validator([
                    self.make_row(window_start=timestamp)
                ])

                self.assertNotEqual(result.returncode, 0)

    def test_duplicate_windows_fail(self):
        row = self.make_row()

        result = self.run_validator([row, row.copy()])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stdout)

    def test_unsorted_windows_fail(self):
        result = self.run_validator([
            self.make_row(
                window_start="2017-07-03T13:00:30+00:00"
            ),
            self.make_row(
                window_start="2017-07-03T13:00:00+00:00"
            ),
        ])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not sorted", result.stdout)

    def test_feature_inconsistency_fails(self):
        invalid_cases = (
            {
                "tcp_inbound_unique_dest_port_count": "4",
                "tcp_inbound_flow_count": "3",
            },
            {
                "tcp_outbound_max_unique_dest_ips_per_dest_port": "3",
                "tcp_outbound_unique_dest_ip_count": "2",
            },
        )

        for changes in invalid_cases:
            with self.subTest(changes=changes):
                result = self.run_validator([
                    self.make_row(**changes)
                ])

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "exceeds",
                    result.stdout,
                )


if __name__ == "__main__":
    unittest.main()
