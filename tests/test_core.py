import unittest
from llamasoc.core import EventValidationError, analyze_events, validate_event


def event(event_id, minute, **extra):
    return {"event_id": event_id, "timestamp": f"2026-10-08T09:{minute:02d}:00Z",
            "event_type": "authentication", "source": "unit-test", **extra}


class CoreTests(unittest.TestCase):
    def test_valid_event_and_ip(self):
        self.assertEqual(validate_event(event("e1", 0, src_ip="192.0.2.1"))["src_ip"], "192.0.2.1")

    def test_missing_fields_rejected(self):
        with self.assertRaises(EventValidationError):
            validate_event({"event_id": "e1"})

    def test_timezone_required(self):
        with self.assertRaises(EventValidationError):
            validate_event({"event_id":"e1","timestamp":"2026-10-08T09:00:00","event_type":"authentication","source":"test"})

    def test_bad_ip_rejected(self):
        with self.assertRaises(EventValidationError):
            validate_event(event("e1", 0, src_ip="not-an-ip"))

    def test_failed_logins_then_success(self):
        result = analyze_events([event("f1",0,username="alex",outcome="failed"),
            event("f2",1,username="alex",outcome="failed"), event("f3",2,username="alex",outcome="failed"),
            event("s1",3,username="alex",outcome="success")])
        self.assertIn("AUTH-001", [a["rule_id"] for a in result["alerts"]])
        self.assertTrue(result["alerts"][0]["requires_human_review"])

    def test_privileged_change(self):
        result = analyze_events([{"event_id":"p1","timestamp":"2026-10-08T09:00:00Z",
            "event_type":"privilege_change","source":"test","action":"grant_admin"}])
        self.assertIn("IAM-001", [a["rule_id"] for a in result["alerts"]])

    def test_mock_indicator(self):
        result = analyze_events([{"event_id":"n1","timestamp":"2026-10-08T09:00:00Z",
            "event_type":"network_connection","source":"test","destination":"198.51.100.23"}],
            threat_indicators={"198.51.100.23"})
        self.assertIn("NET-001", [a["rule_id"] for a in result["alerts"]])

    def test_duplicate_ids_rejected(self):
        result = analyze_events([event("same",0), event("same",1)])
        self.assertEqual(result["summary"]["events_valid"], 1)
        self.assertEqual(result["summary"]["events_rejected"], 1)

    def test_large_transfer(self):
        result = analyze_events([{"event_id":"n1","timestamp":"2026-10-08T09:00:00Z",
            "event_type":"network_connection","source":"test","bytes_out":150000000}])
        self.assertIn("NET-002", [a["rule_id"] for a in result["alerts"]])


if __name__ == "__main__":
    unittest.main()
