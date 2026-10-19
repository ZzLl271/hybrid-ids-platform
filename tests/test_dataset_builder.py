import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

FIELDS = [
    "window_start",
    "monitored_ip",
    "tcp_inbound_flow_count",
    "tcp_outbound_flow_count",
    "tcp_inbound_unique_dest_port_count",
    "tcp_inbound_max_unique_dest_ports_per_src_ip",
    "tcp_inbound_unique_src_ip_count",
    "tcp_outbound_unique_dest_ip_count",
    "tcp_outbound_unique_dest_port_count",
    "tcp_outbound_max_unique_dest_ips_per_dest_port",
]


class TestDatasetBuilder(unittest.TestCase):

    def test_demo_csv_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "features.csv"

            command = [
                sys.executable,
                "-m", "scripts.build_feature_dataset",
                "--input", "samples/eve-demo.json",
                "--monitored-ip", "192.0.2.10",
                "--output", str(output),
            ]

            subprocess.run(
                command, cwd=ROOT,
                capture_output=True, text=True, check=True,
            )

            first_content = output.read_bytes()

            with output.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, FIELDS)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["monitored_ip"], "192.0.2.10")
            self.assertEqual(
                [int(rows[0][field]) for field in FIELDS[2:]],
                [3, 3, 3, 2, 2, 3, 2, 2],
            )

            subprocess.run(
                command, cwd=ROOT,
                capture_output=True, text=True, check=True,
            )

            self.assertEqual(output.read_bytes(), first_content)

    def test_missing_input_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "features.csv"

            result = subprocess.run(
                [
                    sys.executable,
                    "-m", "scripts.build_feature_dataset",
                    "--input", str(Path(directory) / "missing.json"),
                    "--monitored-ip", "192.0.2.10",
                    "--output", str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_malformed_json_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            bad_input = Path(directory) / "bad.json"
            output = Path(directory) / "features.csv"

            sample = (ROOT / "samples/eve-demo.json").read_text(
                encoding="utf-8"
            )
            bad_input.write_text(
                sample + "\n{invalid json\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m", "scripts.build_feature_dataset",
                    "--input", str(bad_input),
                    "--monitored-ip", "192.0.2.10",
                    "--output", str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Invalid JSON on line", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()