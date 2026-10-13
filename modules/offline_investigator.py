
"""Offline rule-based investigation engine for TraceWeaver AI.

This module works locally without Gemini or network access.
Findings are review leads, not proof of malicious activity.
"""

from datetime import datetime, timezone

import pandas as pd


def _text(value):
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()


def _make_finding(title, finding_type, event_ids, reasoning, limitations):
    event_ids = list(dict.fromkeys(event_ids))

    return {
        "finding": title,
        "finding_type": finding_type,
        "evidence_event_ids": event_ids,
        "reasoning": reasoning,
        "confidence": "Low",
        "limitations": limitations,
        "evidence_support": {
            "level": "Rule-based observation; human review required",
            "cited_event_count": len(event_ids),
            "candidate_links_between_cited_events": 0,
            "rationale": (
                "Deterministic rules generate review leads; they do not "
                "establish malicious activity or causation."
            ),
            "is_probability": False,
        },
        "claim_validation": {
            "event_ids_exist": True,
            "source_timestamps_checked": True,
            "claim_semantics_independently_verified": False,
            "review_required": True,
        },
    }


def investigate_events_offline(events, relationships):
    """Analyze supplied security events using deterministic local rules."""

    if events is None or events.empty:
        raise ValueError("No security events are available.")

    if "event_id" not in events.columns:
        raise ValueError("The events DataFrame must contain event_id.")

    if "timestamp" not in events.columns:
        raise ValueError("The events DataFrame must contain timestamp.")

    data = events.copy()
    data["event_id"] = data["event_id"].map(_text)

    if (data["event_id"] == "").any():
        raise ValueError("One or more events have blank event IDs.")

    if data["event_id"].duplicated().any():
        raise ValueError("Duplicate event IDs exist in the source records.")

    data["timestamp"] = pd.to_datetime(
        data["timestamp"], errors="coerce", utc=True
    )

    if data["timestamp"].isna().any():
        raise ValueError(
            "Offline investigation requires valid timestamps "
            "for every event."
        )

    defaults = {
        "source": "",
        "event_type": "",
        "user": "",
        "device": "",
        "ip_address": "",
        "description": "",
        "session_id": "",
        "process_id": "",
    }

    for column, default in defaults.items():
        if column not in data.columns:
            data[column] = default

    data = data.sort_values("timestamp").reset_index(drop=True)
    valid_ids = set(data["event_id"])

    searchable = (
        data["event_type"].fillna("").astype(str)
        + " "
        + data["description"].fillna("").astype(str)
    ).str.lower()

    suspicious_terms = (
        "failed login",
        "login failure",
        "multiple failed",
        "permission modified",
        "privilege escalation",
        "restricted file",
        "blocked outbound",
        "malware detected",
        "endpoint alert",
        "unauthorized access",
        "suspicious login",
        "authentication failure",
        "invalid password",
    )

    findings = []

    # Identify records that deserve manual review.
    for index, row in data.iterrows():
        text = searchable.iloc[index]
        matched_terms = [
            term for term in suspicious_terms if term in text
        ]

        if not matched_terms:
            continue

        event_id = row["event_id"]
        event_type = _text(row["event_type"]) or "Unclassified event"

        findings.append(
            _make_finding(
                title=f"Review event {event_id}: {event_type}",
                finding_type="Observed fact",
                event_ids=[event_id],
                reasoning=(
                    "The supplied event type or description contains "
                    f"security-review term(s): {', '.join(matched_terms)}. "
                    f"Source description: "
                    f"{_text(row['description']) or 'Not supplied'}"
                ),
                limitations=(
                    "Keyword matching cannot determine whether an event "
                    "is malicious or whether access was successful."
                ),
            )
        )

    # Identify repeated authentication-failure entries.
    failed_mask = searchable.str.contains(
        r"failed login|login failure|authentication failure|invalid password",
        regex=True,
        na=False,
    )
    failed_events = data.loc[failed_mask].copy()

    if not failed_events.empty:
        group_fields = ["user", "device"]

        for field in group_fields:
            failed_events[field] = (
                failed_events[field].fillna("").astype(str).str.strip()
            )

        grouped_events = failed_events[
            failed_events[group_fields].ne("").any(axis=1)
        ]

        for group_values, group in grouped_events.groupby(
            group_fields, dropna=False
        ):
            if len(group) < 2:
                continue

            if not isinstance(group_values, tuple):
                group_values = (group_values,)

            description = ", ".join(
                f"{field}={value}"
                for field, value in zip(group_fields, group_values)
                if value
            )

            ids = group["event_id"].tolist()

            findings.append(
                _make_finding(
                    title="Repeated authentication-failure entries",
                    finding_type="Correlated observation",
                    event_ids=ids,
                    reasoning=(
                        f"{len(group)} records contain authentication-failure "
                        f"terms for the same available grouping fields "
                        f"({description})."
                    ),
                    limitations=(
                        "Repeated failures alone do not establish an attack "
                        "or successful access."
                    ),
                )
            )

    # Validate and report candidate relationships supplied by the app.
    if isinstance(relationships, pd.DataFrame):
        relationship_records = relationships.to_dict(orient="records")
    else:
        relationship_records = relationships or []

    valid_relationship_count = 0
    seen_relationships = set()

    for link in relationship_records:
        if not isinstance(link, dict):
            continue

        source = _text(link.get("from_event"))
        target = _text(link.get("to_event"))

        if source not in valid_ids or target not in valid_ids:
            continue

        if source == target:
            continue

        valid_relationship_count += 1
        pair = tuple(sorted((source, target)))

        if pair in seen_relationships:
            continue

        seen_relationships.add(pair)

        findings.append(
            _make_finding(
                title=f"Candidate relationship: {source} ↔ {target}",
                finding_type="Correlated observation",
                event_ids=[source, target],
                reasoning=(
                    "The correlation module supplied a candidate relationship "
                    "between these source events. Review the original records "
                    "and shared signals before drawing conclusions."
                ),
                limitations=(
                    "A heuristic relationship does not establish causation, "
                    "malicious intent, or a common actor."
                ),
            )
        )

    timeline = [
        {
            "event_id": row["event_id"],
            "timestamp": row["timestamp"].isoformat(),
            "description": (
                _text(row["description"])
                or _text(row["event_type"])
                or "Source event"
            ),
        }
        for _, row in data.iterrows()
    ]

    summary = (
        f"Offline rule-based analysis reviewed {len(data)} source events "
        f"and generated {len(findings)} review lead(s). "
        "All leads require manual verification."
        if findings
        else (
            f"Offline rule-based analysis reviewed {len(data)} source events "
            "and found no patterns covered by its current rules. "
            "This does not prove the logs are benign."
        )
    )

    return {
        "incident_summary": summary,
        "overall_assessment": (
            "This report was generated locally using deterministic rules. "
            "It does not use Gemini or another generative model. "
            "No compromise determination has been made."
        ),
        "key_findings": findings,
        "timeline_summary": timeline,
        "missing_evidence": [
            "Confirm event meanings against original system and security logs.",
            "Verify relevant account, device, session, and process context.",
            "Check whether source records are complete and time-synchronized.",
        ],
        "recommended_checks": [
            "Review each finding's cited event IDs in the original logs.",
            "Inspect candidate relationship signals before interpreting them.",
            "Correlate with authorized endpoint, identity, and network records.",
        ],
        "limitations": [
            "Offline mode uses deterministic keyword and grouping rules.",
            "Keyword matches may produce false positives and miss novel patterns.",
            "Candidate relationships do not establish causation.",
            "Absence of findings does not prove that a system is safe.",
        ],
        "analysis_mode": "offline_rule_based",
        "events_analyzed": len(data),
        "candidate_relationships_supplied": valid_relationship_count,
        "generation_time_seconds": None,
        "model_used": "Offline rule-based engine",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_scope": (
            f"All {len(data)} validated source events were inspected locally. "
            "The output is rule-based, not generative AI analysis."
        ),
        "evidence_assessment_method": (
            "Deterministic keyword, grouping, source-ID, and candidate-link "
            "checks. These checks are not probabilities or proof."
        ),
    }
