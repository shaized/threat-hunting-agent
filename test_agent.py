import copy
import json
from pathlib import Path
import unittest

from agent import analyze


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(Path(__file__).with_name("example.json").read_text())

    def test_sequence_references_all_four_events(self):
        self.assertEqual(
            analyze(self.data)["findings"][0]["evidence_ids"],
            ["auth-1", "auth-2", "auth-3", "auth-4"],
        )

    def test_input_order_does_not_change_sequence(self):
        expected = analyze(self.data)
        self.data["events"].reverse()
        self.assertEqual(analyze(self.data), expected)

    def test_repeated_delivery_cannot_inflate_failures(self):
        event = self.data["events"][0]
        self.data["events"] = [
            event,
            copy.deepcopy(event),
            copy.deepcopy(event),
            self.data["events"][-1],
        ]
        result = analyze(self.data)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["duplicates_ignored"], 2)

    def test_conflicting_ids_fail_closed(self):
        event = copy.deepcopy(self.data["events"][0])
        event["outcome"] = "success"
        self.data["events"].append(event)
        with self.assertRaises(ValueError):
            analyze(self.data)

    def test_another_service_does_not_join(self):
        self.data["events"][-1]["service"] = "other-service"
        self.assertEqual(analyze(self.data)["findings"], [])

    def test_another_user_does_not_join(self):
        self.data["events"][-1]["user"] = "another-user"
        self.assertEqual(analyze(self.data)["findings"], [])

    def test_equal_timestamps_do_not_establish_sequence(self):
        for event in self.data["events"]:
            event["timestamp"] = "2026-01-15T10:04:00Z"
        self.assertEqual(analyze(self.data)["findings"], [])

    def test_window_boundary_is_inclusive(self):
        self.data["window_seconds"] = 180
        self.assertEqual(len(analyze(self.data)["findings"]), 1)
        self.data["window_seconds"] = 179
        self.assertEqual(analyze(self.data)["findings"], [])

    def test_success_consumes_only_earlier_failures(self):
        success = copy.deepcopy(self.data["events"][-1])
        success.update(id="auth-5", timestamp="2026-01-15T10:05:00Z")
        self.data["events"].append(success)
        self.assertEqual(len(analyze(self.data)["findings"]), 1)

    def test_fractional_timestamps_and_offsets_order_correctly(self):
        self.data["threshold"] = 1
        self.data["events"] = [self.data["events"][0], self.data["events"][-1]]
        self.data["events"][0]["timestamp"] = "2026-01-15T12:00:00+02:00"
        self.data["events"][1]["timestamp"] = "2026-01-15T10:00:00.100Z"
        self.assertEqual(len(analyze(self.data)["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
