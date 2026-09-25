import unittest
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from scripts.live_telemetry_simulator import generate_event

class TestSprint5Simulator(unittest.TestCase):
    def test_simulator_generates_valid_syslog(self):
        # We need to test the logic of event generation
        event = generate_event(pct_malformed=0)
        self.assertIn("source_name", event)
        self.assertIn("file_format", event)
        self.assertIn("raw_content", event)
        self.assertIn("metadata", event)
        
    def test_simulator_generates_malformed(self):
        # Force a malformed event
        event = generate_event(pct_malformed=100)
        self.assertEqual(event["source_name"], "UNKNOWN-X")
        self.assertTrue(len(event["raw_content"]) > 0)
        
    def test_all_formats_are_covered(self):
        # Sample enough events to ensure formats are generated without crashing
        formats_seen = set()
        for _ in range(50):
            event = generate_event(pct_malformed=0)
            formats_seen.add(event["file_format"])
        
        # Expect at least syslog, json, cef, csv
        self.assertTrue("syslog" in formats_seen)
        self.assertTrue("json" in formats_seen)
        self.assertTrue("cef" in formats_seen)
        self.assertTrue("csv" in formats_seen)
