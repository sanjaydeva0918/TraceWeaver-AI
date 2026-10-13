
import unittest

import pandas as pd

from modules.correlation import build_event_relationships


def make_events(rows):
    return pd.DataFrame(rows)


class TestEventCorrelation(unittest.TestCase):

    def test_shared_device_creates_candidate_link(self):
        events = make_events([
            {
                "event_id": "E1",
                "timestamp": "2026-10-10T10:00:00Z",
                "device": "laptop-01",
                "description": "Login event",
            },
            {
                "event_id": "E2",
                "timestamp": "2026-10-10T10:05:00Z",
                "device": "laptop-01",
                "description": "Session event",
            },
        ])

        links = build_event_relationships(events)

        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["from_event"], "E1")
        self.assertEqual(links[0]["to_event"], "E2")
        self.assertIn("device", links[0]["shared_signals"])
        self.assertTrue(links[0]["requires_human_review"])
        self.assertFalse(links[0]["is_proof_of_causation"])

    def test_time_proximity_alone_does_not_create_link(self):
        events = make_events([
            {
                "event_id": "E1",
                "timestamp": "2026-10-10T10:00:00Z",
                "user": "alice",
                "description": "Routine application event",
            },
            {
                "event_id": "E2",
                "timestamp": "2026-10-10T10:02:00Z",
                "user": "bob",
                "description": "Routine application event",
            },
        ])

        self.assertEqual(build_event_relationships(events), [])

    def test_events_outside_time_window_are_not_linked(self):
        events = make_events([
            {
                "event_id": "E1",
                "timestamp": "2026-10-10T10:00:00Z",
                "user": "alice",
            },
            {
                "event_id": "E2",
                "timestamp": "2026-10-10T11:00:00Z",
                "user": "alice",
            },
        ])

        self.assertEqual(
            build_event_relationships(events, window_minutes=30),
            [],
        )

    def test_missing_required_column_is_rejected(self):
        events = pd.DataFrame([
            {"event_id": "E1"},
        ])

        with self.assertRaisesRegex(ValueError, "timestamp"):
            build_event_relationships(events)

    def test_duplicate_event_ids_are_rejected(self):
        events = make_events([
            {
                "event_id": "E1",
                "timestamp": "2026-10-10T10:00:00Z",
            },
            {
                "event_id": "E1",
                "timestamp": "2026-10-10T10:01:00Z",
            },
        ])

        with self.assertRaisesRegex(ValueError, "unique"):
            build_event_relationships(events)

    def test_invalid_timestamps_are_rejected(self):
        events = make_events([
            {
                "event_id": "E1",
                "timestamp": "not-a-date",
            },
        ])

        with self.assertRaisesRegex(ValueError, "timestamp"):
            build_event_relationships(events)


if __name__ == "__main__":
    unittest.main()
