
"""Explainable, conservative event-correlation rules for TraceWeaver AI.

Candidate relationships are review leads, not proof of causation.
"""

from itertools import combinations

import pandas as pd


DEFAULT_WINDOW_MINUTES = 30

ENTITY_FIELDS = (
    "user",
    "device",
    "ip_address",
    "session_id",
    "process_id",
)

RISK_TERMS = (
    "failed login",
    "login failure",
    "privilege escalation",
    "permission changed",
    "permissions modified",
    "restricted file",
    "sensitive file",
    "malware",
    "blocked connection",
    "endpoint alert",
    "unauthorized",
    "suspicious",
)


def _clean(value):
    """Normalize a value and ignore blank or placeholder fields."""
    if value is None or pd.isna(value):
        return ""

    value = str(value).strip()

    if value.lower() in {
        "",
        "nan",
        "none",
        "null",
        "unknown",
        "n/a",
        "na",
    }:
        return ""

    return value.casefold()


def _event_text(row):
    """Return searchable event text."""
    return " ".join(
        str(row.get(field, "") or "")
        for field in ("event_type", "description")
    ).casefold()


def build_event_relationships(
    events,
    window_minutes=DEFAULT_WINDOW_MINUTES,
):
    """Return conservative, explainable candidate relationships.

    A pair is linked only when:
    1. Both records have valid, distinct event IDs and timestamps.
    2. They are within the configured time window.
    3. They share a non-empty identity/device/network/session/process
       value, or both contain a recognized security-review term.

    Temporal proximity alone never creates a relationship.
    """
    if not isinstance(events, pd.DataFrame):
        raise TypeError("events must be a pandas DataFrame.")

    if events.empty:
        return []

    required = {"event_id", "timestamp"}
    missing = required - set(events.columns)

    if missing:
        raise ValueError(
            "Missing required event columns: "
            + ", ".join(sorted(missing))
        )

    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than zero.")

    data = events.copy()

    data["event_id"] = data["event_id"].astype("string").str.strip()
    data["timestamp"] = pd.to_datetime(
        data["timestamp"],
        errors="coerce",
        utc=True,
    )

    if data["event_id"].isna().any() or data["event_id"].eq("").any():
        raise ValueError("Every event must have a non-empty event_id.")

    if data["event_id"].duplicated().any():
        raise ValueError("event_id values must be unique.")

    if data["timestamp"].isna().any():
        raise ValueError("Every event must have a valid timestamp.")

    for field in ENTITY_FIELDS:
        if field not in data.columns:
            data[field] = ""

    for field in ("event_type", "description"):
        if field not in data.columns:
            data[field] = ""

    data = data.sort_values("timestamp").reset_index(drop=True)

    results = []

    for (_, left), (_, right) in combinations(
        data.iterrows(), 2
    ):
        minutes = abs(
            (right["timestamp"] - left["timestamp"]).total_seconds()
        ) / 60.0

        if minutes > window_minutes:
            continue

        shared = []

        for field in ENTITY_FIELDS:
            left_value = _clean(left.get(field))
            right_value = _clean(right.get(field))

            if left_value and right_value and left_value == right_value:
                shared.append(field)

        left_text = _event_text(left)
        right_text = _event_text(right)

        left_terms = [
            term for term in RISK_TERMS if term in left_text
        ]
        right_terms = [
            term for term in RISK_TERMS if term in right_text
        ]

        shared_risk_context = bool(left_terms and right_terms)

        # Never link events merely because their timestamps are close.
        if not shared and not shared_risk_context:
            continue

        reasons = []

        if shared:
            reasons.append(
                "Shared fields: " + ", ".join(shared)
            )

        if shared_risk_context:
            reasons.append(
                "Both records contain recognized security-review terms"
            )

        if not shared and shared_risk_context and minutes > 10:
            # Require a tighter time window when no entity matches.
            continue

        results.append(
            {
                "from_event": str(left["event_id"]),
                "to_event": str(right["event_id"]),
                "shared_signals": ", ".join(shared) if shared else (
                    "Shared security-review context; no shared entity"
                ),
                "time_delta_minutes": round(minutes, 2),
                "correlation_score": (
                    0.75 if shared and shared_risk_context
                    else 0.60 if shared
                    else 0.35
                ),
                "rationale": "; ".join(reasons),
                "confidence": (
                    "Low"
                    if not shared
                    else "Moderate review priority"
                ),
                "requires_human_review": True,
                "is_proof_of_causation": False,
            }
        )

    return results
