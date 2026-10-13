
import unittest

import pandas as pd

from modules.offline_investigator import investigate_events_offline


class OfflineInvestigatorTests(unittest.TestCase):

    def setUp(self):
        self.events = pd.DataFrame([
            {
                "event_id": "E001",
                "timestamp": "2026-10-13T10:00:00Z",
                "source": "auth",
                "event_type": "Failed login",
                "user": "alex",
                "device": "WS-014",
                "ip_address": "192.0.2.10",
                "description": "Authentication failure",
            },
            {
                "event_id": "E002",
                "timestamp": "2026-10-13T10:02:00Z",
                "source": "auth",
                "event_type": "Failed login",
                "user": "alex",
                "device": "WS-014",
                "ip_address": "192.0.2.10",
                "description": "Authentication failure",
            },
            {
                "event_id": "E003",
                "timestamp": "2026-10-13T10:05:00Z",
                "source": "session",
                "event_type": "Session started",
                "user": "alex",
                "device": "WS-014",
                "ip_address": "192.0.2.10",
                "description": "Normal session event",
            },
        ])

        self.relationships = [
            {
                "from_event": "E001",
                "to_event": "E002",
                "heuristic_score": 0.9,
            }
        ]

    def test_report_contains_required_fields(self):
        report = investigate_events_offline(
            self.events, self.relationships
        )

        for field in (
            "incident_summary",
            "overall_assessment",
            "key_findings",
            "timeline_summary",
            "missing_evidence",
            "recommended_checks",
            "limitations",
            "analysis_mode",
        ):
            self.assertIn(field, report)

        self.assertEqual(report["analysis_mode"], "offline_rule_based")
        self.assertEqual(report["events_analyzed"], 3)

    def test_timeline_contains_every_source_event(self):
        report = investigate_events_offline(
            self.events, self.relationships
        )

        timeline_ids = {
            item["event_id"] for item in report["timeline_summary"]
        }

        self.assertEqual(timeline_ids, {"E001", "E002", "E003"})

    def test_failed_login_pattern_is_flagged_for_review(self):
        report = investigate_events_offline(
            self.events, self.relationships
        )

        titles = [
            finding["finding"] for finding in report["key_findings"]
        ]

        self.assertTrue(
            any("Repeated authentication-failure" in title for title in titles)
        )

    def test_duplicate_event_ids_are_rejected(self):
        invalid = pd.concat(
            [self.events, self.events.iloc[[0]]],
            ignore_index=True,
        )

        with self.assertRaisesRegex(ValueError, "Duplicate event IDs"):
            investigate_events_offline(invalid, self.relationships)

    def test_missing_event_id_column_is_rejected(self):
        invalid = self.events.drop(columns=["event_id"])

        with self.assertRaisesRegex(ValueError, "event_id"):
            investigate_events_offline(invalid, self.relationships)

    def test_invalid_timestamp_is_rejected(self):
        invalid = self.events.copy()
        invalid.loc[0, "timestamp"] = "not-a-timestamp"

        with self.assertRaisesRegex(ValueError, "valid timestamps"):
            investigate_events_offline(invalid, self.relationships)

    def test_empty_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "No security events"):
            investigate_events_offline(self.events.iloc[0:0], [])

    def test_findings_require_human_review(self):
        report = investigate_events_offline(
            self.events, self.relationships
        )

        self.assertTrue(report["key_findings"])

        for finding in report["key_findings"]:
            self.assertTrue(finding["claim_validation"]["review_required"])
            self.assertFalse(
                finding["claim_validation"][
                    "claim_semantics_independently_verified"
                ]
            )
            self.assertFalse(
                finding["evidence_support"]["is_probability"]
            )


if __name__ == "__main__":
    unittest.main()
