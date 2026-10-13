
import unittest
import pandas as pd

from modules.ai_investigator import calibrate_evidence_support


class EvidenceValidationTests(unittest.TestCase):

    def setUp(self):
        self.events = pd.DataFrame([
            {
                "event_id": "E001",
                "timestamp": "2026-10-13T10:00:00Z"
            },
            {
                "event_id": "E002",
                "timestamp": "2026-10-13T10:02:00Z"
            },
        ])

    def test_unknown_event_id_is_rejected(self):
        """Unknown event IDs must raise a validation error."""
        with self.assertRaisesRegex(
            ValueError, "Unknown source event IDs"
        ):
            calibrate_evidence_support(
                ["E001", "UNKNOWN"], self.events, []
            )

    def test_empty_citations_are_insufficient(self):
        """Empty citations must not be treated as evidence."""
        result = calibrate_evidence_support(
            [], self.events, []
        )

        self.assertEqual(
            result["cited_event_count"], 0
        )
        self.assertFalse(
            result["is_probability"]
        )

    def test_one_valid_citation_is_counted(self):
        """A valid source event must be counted."""
        result = calibrate_evidence_support(
            ["E001"], self.events, []
        )

        self.assertEqual(
            result["cited_event_count"], 1
        )
        self.assertFalse(
            result["is_probability"]
        )

    def test_candidate_link_is_not_a_probability(self):
        """A candidate relationship must not be presented as probability."""
        relationships = [
            {
                "from_event": "E001",
                "to_event": "E002",
                "heuristic_score": 0.9
            }
        ]

        result = calibrate_evidence_support(
            ["E001", "E002"],
            self.events,
            relationships
        )

        self.assertEqual(
            result["candidate_links_between_cited_events"], 1
        )
        self.assertFalse(
            result["is_probability"]
        )
        self.assertIn(
            "do not", result["rationale"].lower()
        )


if __name__ == "__main__":
    unittest.main()
