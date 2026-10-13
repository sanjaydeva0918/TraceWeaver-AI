"""TraceWeaver AI Streamlit Dashboard."""

import hashlib

import io

import json

from datetime import datetime, timezone

from pathlib import Path

from xml.sax.saxutils import escape

import pandas as pd

import plotly.express as px

import plotly.graph_objects as go

import streamlit as st

from modules.correlation import build_event_relationships

from modules.ai_investigator import investigate_events

from modules.offline_investigator import investigate_events_offline

# =========================================================

# PAGE CONFIGURATION

# =========================================================

st.set_page_config(
    page_title="TraceWeaver AI",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

REPORT_KEY = "traceweaver_report"

SOURCE_KEY = "traceweaver_report_source"

# =========================================================

# VISUAL THEME

# =========================================================

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(
            180deg,
            rgba(19, 54, 93, 0.035) 0%,
            rgba(19, 138, 145, 0.015) 35%,
            transparent 70%
        );
    }
    [data-testid="stSidebar"] {
        border-right: 1px solid rgba(100, 116, 139, 0.20);
    }
    [data-testid="stMetric"] {
        background: var(--secondary-background-color);
        border: 1px solid rgba(100, 116, 139, 0.22);
        border-radius: 12px;
        padding: 14px 16px;
    }
    div[data-testid="stMetricValue"] {
        font-weight: 700;
    }
    div[data-testid="stTabs"] button {
        font-weight: 600;
    }
    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(100, 116, 139, 0.22);
        border-radius: 10px;
        overflow: hidden;
    }
    div[data-testid="stAlert"] {
        border-radius: 10px;
    }
    h1, h2, h3 {
        letter-spacing: -0.02em;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# =========================================================

# CSV LOADING AND NORMALIZATION

# =========================================================

def normalize_logs(uploaded_file):
    """Load and normalize common security log columns."""
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
    else:
        sample_path = (
            Path(__file__).resolve().parent
            / "data"
            / "sample_security_logs.csv"
        )
        if not sample_path.exists():
            return pd.DataFrame()
        data = pd.read_csv(sample_path)

    # Normalize column names.

    data.columns = [
        str(column).strip().lower().replace(" ", "_")
        for column in data.columns
    ]
    aliases = {
        "eventid": "event_id",
        "time": "timestamp",
        "datetime": "timestamp",
        "event_time": "timestamp",
        "eventtype": "event_type",
        "ip": "ip_address",
        "ipaddress": "ip_address",
        "hostname": "device",
        "username": "user",
    }
    data = data.rename(
        columns={
            old: new
            for old, new in aliases.items()
            if old in data.columns and new not in data.columns
        }
    )
    if "timestamp" not in data.columns:
        raise ValueError(
            "CSV must contain timestamp, time, datetime, "
            "or event_time."
        )

    # Generate IDs when the CSV does not contain them.

    if "event_id" not in data.columns:
        data["event_id"] = [
            f"E{index + 1:03d}"
            for index in range(len(data))
        ]
    if data["event_id"].isna().any():
        raise ValueError("Some event IDs are empty.")
    data["event_id"] = (
        data["event_id"].astype(str).str.strip()
    )
    if (data["event_id"] == "").any():
        raise ValueError("Some event IDs are blank.")
    if data["event_id"].duplicated().any():
        duplicates = (
            data.loc[
                data["event_id"].duplicated(),
                "event_id",
            ]
            .unique()
            .tolist()
        )
        raise ValueError(
            "Duplicate event IDs found: "
            + ", ".join(duplicates)
        )

    # Normalize timestamps to UTC.

    data["timestamp"] = pd.to_datetime(
        data["timestamp"],
        errors="coerce",
        utc=True,
    )
    invalid_count = int(data["timestamp"].isna().sum())
    if invalid_count:
        st.warning(
            f"{invalid_count} row(s) have invalid timestamps "
            "and were excluded from the normalized event set."
        )
    data = data.dropna(subset=["timestamp"]).copy()

    # Add optional columns if missing.

    defaults = {
        "source": "Unknown",
        "event_type": "Unclassified",
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
    return (
        data.sort_values("timestamp")
        .reset_index(drop=True)
    )

# =========================================================

# PDF REPORT GENERATION

# =========================================================

def build_investigation_pdf(report):
    """Create a professional PDF investigation report."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import (
        getSampleStyleSheet,
        ParagraphStyle,
    )
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
    )
    buffer = io.BytesIO()
    navy = colors.HexColor("#17365D")
    pale = colors.HexColor("#EDF4F8")
    grey = colors.HexColor("#5B6573")
    border = colors.HexColor("#D5DEE7")
    white = colors.white
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="TWTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            textColor=navy,
            alignment=1,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TWSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=grey,
            alignment=1,
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TWSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=navy,
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TWBody",
            parent=styles["BodyText"],
            fontSize=8.7,
            leading=12,
            spaceAfter=4,
            splitLongWords=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TWCell",
            parent=styles["BodyText"],
            fontSize=7.3,
            leading=9.5,
            splitLongWords=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TWFinding",
            parent=styles["Heading3"],
            fontSize=10,
            leading=13,
            textColor=navy,
            spaceBefore=4,
            spaceAfter=4,
            keepWithNext=True,
        )
    )

    def para(value, style="TWBody"):
        """Safely format values for ReportLab paragraphs."""
        if value is None:
            value = "Not provided"
        if isinstance(value, (dict, list)):
            value = json.dumps(
                value,
                ensure_ascii=False,
                default=str,
            )
        safe = escape(str(value)).replace("\n", "<br/>")
        return Paragraph(safe, styles[style])

    def footer(canvas, doc):
        """Draw the report footer."""
        canvas.saveState()
        page_width, _ = A4
        canvas.setStrokeColor(border)
        canvas.line(
            18 * mm,
            14 * mm,
            page_width - 18 * mm,
            14 * mm,
        )
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(grey)
        canvas.drawString(
            18 * mm,
            9 * mm,
            "TraceWeaver AI | Investigation Aid",
        )
        canvas.drawRightString(
            page_width - 18 * mm,
            9 * mm,
            f"Page {doc.page}",
        )
        canvas.restoreState()
    findings = report.get("key_findings", [])
    timeline = report.get("timeline_summary", [])
    relationships = report.get("candidate_relationships", [])
    if not isinstance(findings, list):
        findings = []
    if not isinstance(timeline, list):
        timeline = []
    if not isinstance(relationships, list):
        relationships = []
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=15 * mm,
        bottomMargin=20 * mm,
        title="TraceWeaver AI Investigation Report",
        author="TraceWeaver AI",
    )
    generated = report.get(
        "generated_at_utc",
        datetime.now(timezone.utc).isoformat(),
    )

    # -----------------------------------------------------

    # Report header and executive summary

    # -----------------------------------------------------

    story = [
        Spacer(1, 4 * mm),
        para("TRACEWEAVER AI", "TWTitle"),
        para(
            "DIGITAL INCIDENT RECONSTRUCTION REPORT",
            "TWSubtitle",
        ),
        para(f"Generated at (UTC): {generated}"),
        para(
            f"Model: {report.get('model_used', 'Not recorded')}"
        ),
        para(
            "Analysis mode: "
            f"{report.get('analysis_mode', 'Not recorded')}"
        ),
        para(
            "Request duration: "
            f"{report.get('generation_time_seconds', 'Not recorded')} "
            "seconds"
        ),
        para(
            "Source events: "
            f"{report.get('events_analyzed', 'Not recorded')} | "
            "Candidate relationships: "
            f"{report.get('candidate_relationships_supplied', 'Not recorded')}"
        ),
        para("Executive Summary", "TWSection"),
        para(
            report.get(
                "incident_summary",
                "No summary provided.",
            )
        ),
        para("Overall Assessment", "TWSection"),
        para(
            report.get(
                "overall_assessment",
                "No assessment provided.",
            )
        ),
    ]

    # -----------------------------------------------------

    # Report metrics

    # -----------------------------------------------------

    metric_rows = [
        [
            para("METRIC", "TWCell"),
            para("VALUE", "TWCell"),
        ],
        [
            para("Source events supplied", "TWCell"),
            para(report.get("events_analyzed", "N/A"), "TWCell"),
        ],
        [
            para("Candidate relationships", "TWCell"),
            para(
                report.get(
                    "candidate_relationships_supplied",
                    "N/A",
                ),
                "TWCell",
            ),
        ],
        [
            para("Key findings", "TWCell"),
            para(len(findings), "TWCell"),
        ],
        [
            para("Timeline entries", "TWCell"),
            para(len(timeline), "TWCell"),
        ],
    ]
    metric_table = Table(
        metric_rows,
        colWidths=[95 * mm, 65 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )
    metric_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), navy),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [white, pale],
                ),
                ("GRID", (0, 0), (-1, -1), 0.4, border),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend(
        [
            para("Report Metrics", "TWSection"),
            metric_table,
        ]
    )

    # -----------------------------------------------------

    # Candidate relationship review

    # -----------------------------------------------------

    relationship_rows = [
        [
            para("FROM", "TWCell"),
            para("TO", "TWCell"),
            para("DELTA (MIN)", "TWCell"),
            para("SHARED SIGNALS", "TWCell"),
            para("REVIEW STATUS", "TWCell"),
        ]
    ]
    for link in relationships[:100]:
        if not isinstance(link, dict):
            continue
        relationship_rows.append(
            [
                para(link.get("from_event", "Unknown"), "TWCell"),
                para(link.get("to_event", "Unknown"), "TWCell"),
                para(
                    link.get("time_delta_minutes", "N/A"),
                    "TWCell",
                ),
                para(
                    link.get("shared_signals", "Not recorded"),
                    "TWCell",
                ),
                para("Human review required", "TWCell"),
            ]
        )
    story.append(
        para("Candidate Relationship Review", "TWSection")
    )
    story.append(
        para(
            "These links are rule-generated review leads. "
            "Shared signals and timing do not establish causation."
        )
    )
    if len(relationship_rows) > 1:
        relationship_table = Table(
            relationship_rows,
            colWidths=[
                18 * mm,
                18 * mm,
                25 * mm,
                57 * mm,
                42 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )
        relationship_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), navy),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [white, pale],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.35, border),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(relationship_table)
    else:
        story.append(
            para("No candidate relationships were recorded.")
        )

    # -----------------------------------------------------

    # Findings and evidence

    # -----------------------------------------------------

    story.extend(
        [
            para("Key Findings and Evidence", "TWSection"),
            para(
                "Citation coverage describes referenced records; "
                "it does not independently verify the meaning "
                "or truth of a finding."
            ),
        ]
    )
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue
        support = finding.get("evidence_support", {})
        if not isinstance(support, dict):
            support = {}
        validation = finding.get("claim_validation", {})
        if not isinstance(validation, dict):
            validation = {}
        evidence_ids = finding.get("evidence_event_ids", [])
        if not isinstance(evidence_ids, list):
            evidence_ids = []
        warnings = finding.get("validation_warnings", [])
        if not isinstance(warnings, list):
            warnings = []
        block = [
            para(
                f"Finding {index}: "
                f"{finding.get('finding', 'Untitled finding')}",
                "TWFinding",
            ),
            para(
                f"Type: {finding.get('finding_type', 'Unclassified')}"
            ),
            para(
                "Model-assessed confidence: "
                f"{finding.get('confidence', 'Not provided')}"
            ),
            para(
                "Cited source event IDs: "
                + (", ".join(map(str, evidence_ids)) or "None")
            ),
            para(
                "Citation coverage: "
                f"{support.get('level', 'Not assessed')}"
            ),
            para(
                "Coverage notes: "
                f"{support.get('rationale', 'Not provided')}"
            ),
            para(
                f"Reasoning: {finding.get('reasoning', 'Not provided')}"
            ),
            para(
                "Limitations: "
                f"{finding.get('limitations', 'Not provided')}"
            ),
            para(
                "Claim semantics independently verified: "
                f"{validation.get('claim_semantics_independently_verified', False)}"
            ),
        ]
        for warning in warnings:
            block.append(
                para(f"Validation warning: {warning}")
            )
        block.append(Spacer(1, 3 * mm))
        story.append(KeepTogether(block))

    # -----------------------------------------------------

    # Chronological timeline

    # -----------------------------------------------------

    story.append(
        para("Chronological Timeline", "TWSection")
    )
    timeline_rows = [
        [
            para("TIMESTAMP", "TWCell"),
            para("EVENT ID", "TWCell"),
            para("DESCRIPTION", "TWCell"),
        ]
    ]
    for item in timeline:
        if not isinstance(item, dict):
            continue
        timeline_rows.append(
            [
                para(item.get("timestamp", "Unknown"), "TWCell"),
                para(item.get("event_id", "Unknown"), "TWCell"),
                para(item.get("description", ""), "TWCell"),
            ]
        )
    if len(timeline_rows) > 1:
        timeline_table = Table(
            timeline_rows,
            colWidths=[42 * mm, 22 * mm, 96 * mm],
            repeatRows=1,
            hAlign="LEFT",
        )
        timeline_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), navy),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [white, pale],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.35, border),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(timeline_table)
    else:
        story.append(
            para("No timeline entries were supplied.")
        )

    # -----------------------------------------------------

    # Missing evidence, recommended checks, limitations

    # -----------------------------------------------------

    for field, heading in [
        ("missing_evidence", "Missing Evidence"),
        ("recommended_checks", "Recommended Investigation Checks"),
        ("limitations", "Report Limitations"),
    ]:
        story.append(para(heading, "TWSection"))
        items = report.get(field, [])
        if not isinstance(items, list) or not items:
            story.append(para("No items supplied."))
        else:
            for item in items:
                story.append(para(f"• {item}"))

    # -----------------------------------------------------

    # Validation and scope

    # -----------------------------------------------------

    story.extend(
        [
            para("Validation and Scope", "TWSection"),
            para(
                report.get(
                    "analysis_scope",
                    "Scope not recorded.",
                )
            ),
            para(
                report.get(
                    "evidence_assessment_method",
                    "Evidence assessment method not recorded.",
                )
            ),
            Spacer(1, 2 * mm),
            para(
                "IMPORTANT: This report is an investigative aid, "
                "not a verdict. Candidate relationships, AI confidence, "
                "and citation coverage do not prove causation, malicious "
                "intent, or compromise. Verify important conclusions "
                "against original logs and independent evidence."
            ),
        ]
    )
    doc.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer,
    )
    buffer.seek(0)
    return buffer.getvalue()

# =========================================================

# HEADER AND SIDEBAR

# =========================================================

st.title("🕵️ TraceWeaver AI")

st.caption(
    "Evidence-calibrated digital incident reconstruction "
    "and investigation workspace"
)

with st.sidebar:
    st.header("Investigation Setup")
    uploaded_file = st.file_uploader(
        "Upload security logs",
        type=["csv"],
        help=(
            "Upload authorized security logs. Review data-handling "
            "requirements before sending data to an external AI service."
        ),
    )
    st.caption(
        "Required column: timestamp. Common fields such as event_id, "
        "user, device, and ip_address are supported."
    )
    st.divider()
    st.caption(
        "AI findings are investigative assistance, not proof "
        "of causation or compromise."
    )

# =========================================================

# LOAD DATA AND INVALIDATE STALE REPORTS

# =========================================================

try:
    df = normalize_logs(uploaded_file)
except Exception as exc:
    st.error("Could not load or normalize the log file.")
    st.exception(exc)
    st.stop()
if df.empty:
    st.warning(
        "No usable events were found. Upload a CSV or add "
        "data/sample_security_logs.csv to the project."
    )
    st.stop()
if uploaded_file is not None:
    source_bytes = uploaded_file.getvalue()
    source_signature = (
        f"{uploaded_file.name}:{uploaded_file.size}:"
        f"{hashlib.sha256(source_bytes).hexdigest()}"
    )
else:
    sample_path = (
        Path(__file__).resolve().parent
        / "data"
        / "sample_security_logs.csv"
    )
    if sample_path.exists():
        source_signature = hashlib.sha256(
            sample_path.read_bytes()
        ).hexdigest()
    else:
        source_signature = "no_sample_file"

# Include normalized data so changes invalidate previous reports.

normalized_bytes = df.to_csv(index=False).encode("utf-8")

fingerprint = hashlib.sha256(
    source_signature.encode("utf-8") + normalized_bytes
).hexdigest()

if st.session_state.get(SOURCE_KEY) != fingerprint:
    st.session_state.pop(REPORT_KEY, None)
    st.session_state[SOURCE_KEY] = fingerprint

# =========================================================

# BUILD CANDIDATE RELATIONSHIPS

# =========================================================

try:
    relationships = build_event_relationships(df)
    if isinstance(relationships, pd.DataFrame):
        relationships = relationships.to_dict(orient="records")
    if relationships is None:
        relationships = []
    if not isinstance(relationships, list):
        raise ValueError(
            "build_event_relationships() must return a list "
            "of dictionaries or a DataFrame."
        )
except Exception as exc:
    st.error("Could not calculate candidate event relationships.")
    st.exception(exc)
    st.stop()

# =========================================================

# INPUT VALIDATION

# =========================================================

st.subheader("1. Input Validation")

m1, m2, m3, m4 = st.columns(4)

m1.metric("Events loaded", len(df))

m2.metric("Unique event IDs", df["event_id"].nunique())

m3.metric("Candidate relationships", len(relationships))

m4.metric(
    "Distinct devices",
    df["device"].replace("", pd.NA).nunique(),
)

st.success(
    "Logs loaded and timestamps normalized to UTC. "
    "Review the records before interpreting results."
)

# =========================================================

# EVENT TIMELINE

# =========================================================

st.divider()

st.subheader("2. Event Timeline")

fig = px.scatter(
    df,
    x="timestamp",
    y="event_type",
    color="source",
    hover_data=[
        "event_id",
        "user",
        "device",
        "ip_address",
        "description",
    ],
    title="Security Events in Chronological Order",
)

fig.update_layout(
    height=420,
    xaxis_title="Timestamp (UTC)",
    yaxis_title="Event Type",
    legend_title="Source",
)

st.plotly_chart(fig, use_container_width=True)

# =========================================================

# CANDIDATE RELATIONSHIP TABLE AND GRAPH

# =========================================================

st.divider()

st.subheader("3. Candidate Event Relationships")

if relationships:
    rel_df = pd.DataFrame(relationships)
    st.dataframe(
        rel_df,
        use_container_width=True,
        hide_index=True,
    )
    if {"from_event", "to_event"}.issubset(rel_df.columns):
        event_ids = df["event_id"].astype(str).tolist()
        positions = {
            event_id: index
            for index, event_id in enumerate(event_ids)
        }
        graph = go.Figure()
        for _, link in rel_df.iterrows():
            start = str(link["from_event"])
            end = str(link["to_event"])
            if start not in positions or end not in positions:
                continue
            graph.add_trace(
                go.Scatter(
                    x=[positions[start], positions[end]],
                    y=[0, 0],
                    mode="lines",
                    line=dict(color="#64748b", width=1),
                    text=[
                        f"{start} → {end}: "
                        f"{link.get('shared_signals', 'Shared signals unknown')}"
                    ],
                    hoverinfo="text",
                    showlegend=False,
                )
            )
        graph.add_trace(
            go.Scatter(
                x=list(range(len(event_ids))),
                y=[0] * len(event_ids),
                mode="markers+text",
                text=event_ids,
                textposition="top center",
                marker=dict(size=12, color="#22a6b3"),
                hovertext=(
                    df["event_id"].astype(str)
                    + " | "
                    + df["description"].astype(str)
                ),
                hoverinfo="text",
                showlegend=False,
            )
        )
        graph.update_layout(
            title="Candidate Relationship Map",
            height=280,
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            margin=dict(l=20, r=20, t=50, b=20),
        )
        st.plotly_chart(graph, use_container_width=True)
    st.caption(
        "Candidate relationships are heuristic links, "
        "not proof of causation."
    )
else:
    st.info("No candidate relationships were found.")

# =========================================================

# NORMALIZED EVENT RECORDS

# =========================================================

st.divider()

st.subheader("4. Normalized Event Records")

st.dataframe(
    df,
    use_container_width=True,
    hide_index=True,
)

with st.expander("Inspect an individual event"):
    selected_id = st.selectbox(
        "Choose event ID",
        options=df["event_id"].astype(str).tolist(),
        key="source_event_inspector",
    )
    selected_rows = df[
        df["event_id"].astype(str) == selected_id
    ]
    if not selected_rows.empty:
        st.json(
            selected_rows.iloc[0].to_dict(),
            expanded=True,
        )

# =========================================================

# SECURITY INVESTIGATION

# =========================================================

st.divider()

st.subheader("5. Security Investigation")

st.write(
    "Analyze supplied events and candidate relationships to produce "
    "an evidence-linked investigation report. Offline mode works "
    "locally without Gemini API calls."
)

investigation_mode = st.radio(
    "Choose investigation mode",
    options=["Offline Mode", "Gemini AI Mode"],
    index=0,
    horizontal=True,
    help=(
        "Offline Mode uses deterministic local rules. "
        "Gemini AI Mode requires available API quota."
    ),
    key="traceweaver_investigation_mode",
)

if investigation_mode == "Offline Mode":
    st.info(
        "Offline mode selected: no Gemini API call will be made. "
        "Findings are review leads, not proof of malicious activity."
    )
else:
    st.warning(
        "Gemini AI mode uses your configured API and may be subject "
        "to quota limits."
    )
if st.button(
    "Run Investigation",
    type="primary",
    key="run_traceweaver_investigation",
):
    try:
        with st.spinner("Analyzing source records..."):

            # Run the selected investigation engine.

            if investigation_mode == "Offline Mode":
                generated_report = investigate_events_offline(
                    df,
                    relationships,
                )
                generated_report["analysis_mode"] = (
                    "offline_rule_based"
                )
                generated_report["model_used"] = (
                    "Offline rule-based engine"
                )
            else:
                generated_report = investigate_events(
                    df,
                    relationships,
                )

                # Accept JSON text or a dictionary from Gemini.

                if isinstance(generated_report, str):
                    try:
                        generated_report = json.loads(
                            generated_report
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            "investigate_events() returned invalid JSON."
                        ) from exc
                if isinstance(generated_report, dict):
                    generated_report["analysis_mode"] = "gemini_ai"

        # Validate the generated report.

        if not isinstance(generated_report, dict):
            raise ValueError(
                "The investigation engine must return a dictionary."
            )
        required_fields = [
            "incident_summary",
            "overall_assessment",
            "key_findings",
            "timeline_summary",
            "missing_evidence",
            "recommended_checks",
            "limitations",
        ]
        missing_fields = [
            field
            for field in required_fields
            if field not in generated_report
        ]
        if missing_fields:
            raise ValueError(
                "Report is missing fields: "
                + ", ".join(missing_fields)
            )
        list_fields = [
            "key_findings",
            "timeline_summary",
            "missing_evidence",
            "recommended_checks",
            "limitations",
        ]
        for field in list_fields:
            if not isinstance(generated_report[field], list):
                raise ValueError(
                    f"{field} must be a list."
                )

        # Application-controlled metadata.

        generated_report["events_analyzed"] = len(df)
        generated_report["candidate_relationships_supplied"] = (
            len(relationships)
        )

# Retain candidate links for the PDF report.

        generated_report["candidate_relationships"] = [
            dict(item)
            for item in relationships[:100]
            if isinstance(item, dict)
        ]

# =========================================================

        # =========================================================
        # VALIDATE FINDING REFERENCES AGAINST SOURCE EVENTS
        # =========================================================

        source_event_ids = set(df["event_id"].astype(str))

        # Validate against all calculated relationships, not only the
        # first 100 stored for PDF presentation.
        valid_relationships = [
            item for item in relationships
            if isinstance(item, dict)
        ]
        for finding in generated_report.get("key_findings", []):
            if not isinstance(finding, dict):
                continue
            cited_ids = finding.get("evidence_event_ids", [])
            if not isinstance(cited_ids, list):
                cited_ids = []
            cited_ids = [str(event_id) for event_id in cited_ids]
            cited_set = set(cited_ids)
            unknown_ids = sorted(cited_set - source_event_ids)

            # Count links only when both endpoints are cited.
            linked_pairs = set()
            for link in valid_relationships:
                start = str(link.get("from_event", ""))
                end = str(link.get("to_event", ""))
                if (
                    start in cited_set
                    and end in cited_set
                    and start in source_event_ids
                    and end in source_event_ids
                    and start != end
                ):
                    linked_pairs.add(tuple(sorted((start, end))))
            support = finding.get("evidence_support")
            if not isinstance(support, dict):
                support = {}
            support["cited_event_count"] = len(
                cited_set & source_event_ids
            )
            support["candidate_links_between_cited_events"] = len(
                linked_pairs
            )
            support["is_probability"] = False
            support["rationale"] = (
                "Source IDs and candidate links were checked against "
                "the supplied records. These checks do not independently "
                "verify the finding's meaning or establish causation."
            )
            finding["evidence_support"] = support

            # Event-ID checks cannot independently verify claim meaning.
            validation = finding.get("claim_validation")
            if not isinstance(validation, dict):
                validation = {}
            validation["event_ids_exist"] = not unknown_ids
            validation["source_timestamps_checked"] = (
                not unknown_ids
                and "timestamp" in df.columns
                and df["timestamp"].notna().all()
            )
            validation["claim_semantics_independently_verified"] = False
            validation["review_required"] = True
            finding["claim_validation"] = validation
            if unknown_ids:
                warnings = finding.get("validation_warnings", [])
                if not isinstance(warnings, list):
                    warnings = []
                warning = (
                    "Unknown source event ID(s): "
                    + ", ".join(unknown_ids)
                )
                if warning not in warnings:
                    warnings.append(warning)
                finding["validation_warnings"] = warnings
        generated_report["generated_at_utc"] = (
            datetime.now(timezone.utc).isoformat()
        )

        # Store the completed report.
        st.session_state[REPORT_KEY] = generated_report
        st.session_state[SOURCE_KEY] = fingerprint
        st.success(
            f"{investigation_mode} investigation completed successfully."
        )
    except Exception as exc:
        st.error("The investigation could not be completed.")
        st.error(f"{type(exc).__name__}: {exc}")

# REPORT DISPLAY

# =========================================================

report = st.session_state.get(REPORT_KEY)

if not isinstance(report, dict):
    st.info(
        "Run an investigation to view evidence assessments "
        "and download JSON and PDF reports."
    )
    st.stop()
findings = report.get("key_findings", [])

timeline = report.get("timeline_summary", [])

missing = report.get("missing_evidence", [])

recommendations = report.get("recommended_checks", [])

limitations = report.get("limitations", [])

if not isinstance(findings, list):
    findings = []
if not isinstance(timeline, list):
    timeline = []
if not isinstance(missing, list):
    missing = []
if not isinstance(recommendations, list):
    recommendations = []
if not isinstance(limitations, list):
    limitations = []

# =========================================================

# INVESTIGATION OVERVIEW

# =========================================================

st.divider()

st.markdown("### Investigation Overview")

c1, c2, c3 = st.columns(3)

c1.metric(
    "Events analyzed",
    report.get("events_analyzed", len(df)),
)

c2.metric(
    "Key findings",
    len(findings),
)

c3.metric(
    "Candidate relationships",
    report.get(
        "candidate_relationships_supplied",
        len(relationships),
    ),
)

elapsed = report.get("generation_time_seconds")

if elapsed is not None:
    st.caption(f"Request duration: {elapsed} seconds")
attempt_times = report.get("request_attempt_times_seconds")

if isinstance(attempt_times, list):
    st.caption(
        f"Individual request durations: {attempt_times} seconds"
    )
st.caption(
    f"Model: {report.get('model_used', 'Not recorded')}"
)

st.markdown("#### Incident Summary")

st.write(
    report.get(
        "incident_summary",
        "No summary provided.",
    )
)

st.markdown("#### Overall Assessment")

st.info(
    report.get(
        "overall_assessment",
        "No assessment provided.",
    )
)

# =========================================================

# INTERACTIVE REPORT TABS

# =========================================================

(
    tab_findings,
    tab_evidence,
    tab_timeline,
    tab_actions,
    tab_limits,
) = st.tabs(
    [
        "Key Findings",
        "Evidence Explorer",
        "Timeline",
        "Investigation Actions",
        "Limitations",
    ]
)

# ---------------------------------------------------------

# KEY FINDINGS

# ---------------------------------------------------------

with tab_findings:
    if not findings:
        st.info("No key findings were returned.")
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue
        support = finding.get("evidence_support", {})
        if not isinstance(support, dict):
            support = {}
        validation = finding.get("claim_validation", {})
        if not isinstance(validation, dict):
            validation = {}
        cited_ids = finding.get("evidence_event_ids", [])
        if not isinstance(cited_ids, list):
            cited_ids = []
        warnings = finding.get("validation_warnings", [])
        if not isinstance(warnings, list):
            warnings = []
        with st.container(border=True):
            st.markdown(
                f"#### Finding {index}: "
                f"{finding.get('finding', 'Untitled finding')}"
            )
            st.markdown("**Finding type**")
            st.write(
                finding.get("finding_type", "Unclassified")
            )
            st.markdown("**Evidence citation coverage**")
            st.info(
                support.get("level", "Not assessed")
            )
            st.caption(
                support.get(
                    "rationale",
                    "No coverage explanation available.",
                )
            )
            col1, col2 = st.columns(2)
            col1.metric(
                "Cited source events",
                support.get(
                    "cited_event_count",
                    len(cited_ids),
                ),
            )
            col2.metric(
                "Candidate links among cited events",
                support.get(
                    "candidate_links_between_cited_events",
                    0,
                ),
            )
            st.markdown("**Model-assessed confidence**")
            st.write(
                finding.get("confidence", "Not provided")
            )
            st.markdown("**Evidence event IDs**")
            st.write(
                " · ".join(map(str, cited_ids))
                if cited_ids
                else "No event IDs cited."
            )
            if validation:
                st.markdown("**Claim validation status**")
                st.write(
                    "Source event IDs exist: "
                    f"{validation.get('event_ids_exist', False)}"
                )
                st.write(
                    "Claim semantics independently verified: "
                    f"{validation.get('claim_semantics_independently_verified', False)}"
                )
                if validation.get("review_required", True):
                    st.warning(
                        "Human review is required. Source-ID validation "
                        "does not verify the claim's meaning."
                    )
            for warning in warnings:
                st.warning(str(warning))
            with st.expander("Reasoning and limitations"):
                st.markdown("**Reasoning**")
                st.write(
                    finding.get("reasoning", "Not provided.")
                )
                st.markdown("**Finding limitations**")
                st.write(
                    finding.get("limitations", "Not provided.")
                )
    st.caption(
        "Citation coverage describes referenced records. It does not "
        "prove a claim is true, establish causation, or confirm compromise."
    )

# ---------------------------------------------------------

# EVIDENCE EXPLORER

# ---------------------------------------------------------

with tab_evidence:
    st.markdown("#### Inspect a source event")
    selected_event_id = st.selectbox(
        "Select an event",
        options=df["event_id"].astype(str).tolist(),
        key="traceweaver_evidence_event",
    )
    event_rows = df[
        df["event_id"].astype(str) == selected_event_id
    ]
    st.dataframe(
        event_rows,
        use_container_width=True,
        hide_index=True,
    )
    st.markdown("#### Findings citing this event")
    matched = []
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue
        ids = finding.get("evidence_event_ids", [])
        if isinstance(ids, list) and selected_event_id in map(str, ids):
            matched.append((index, finding))
    if matched:
        for index, finding in matched:
            st.markdown(
                f"**Finding {index}:** "
                f"{finding.get('finding', 'Untitled finding')}"
            )
    else:
        st.info(
            "No finding cites this event. This does not mean the event "
            "is irrelevant to the investigation."
        )

# ---------------------------------------------------------

# TIMELINE

# ---------------------------------------------------------

with tab_timeline:
    st.markdown("#### AI Timeline Summary")
    if timeline:
        st.dataframe(
            pd.DataFrame(timeline),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No AI timeline entries were returned.")
    st.markdown("#### Original Source Timeline")
    st.dataframe(
        df.sort_values("timestamp"),
        use_container_width=True,
        hide_index=True,
    )

# ---------------------------------------------------------

# INVESTIGATION ACTIONS

# ---------------------------------------------------------

with tab_actions:
    left, right = st.columns(2)
    with left:
        st.markdown("#### Missing Evidence")
        if missing:
            for item in missing:
                st.markdown(f"- {item}")
        else:
            st.write("No missing-evidence items returned.")
    with right:
        st.markdown("#### Recommended Checks")
        if recommendations:
            for item in recommendations:
                st.markdown(f"- {item}")
        else:
            st.write("No recommended checks returned.")

# ---------------------------------------------------------

# LIMITATIONS

# ---------------------------------------------------------

with tab_limits:
    if limitations:
        for item in limitations:
            st.markdown(f"- {item}")
    else:
        st.info("No general limitations were returned.")
    st.warning(
        "Shared identifiers and nearby timestamps do not prove causation. "
        "Verify important conclusions against original logs."
    )
    st.markdown("#### Evidence Assessment Method")
    st.write(
        report.get(
            "evidence_assessment_method",
            "No assessment method recorded.",
        )
    )
    st.markdown("#### Analysis Scope")
    st.write(
        report.get(
            "analysis_scope",
            "No analysis-scope information recorded.",
        )
    )

# =========================================================

# JSON AND PDF EXPORTS

# =========================================================

st.divider()

st.markdown("### Export Investigation Report")

json_bytes = json.dumps(
    report,
    ensure_ascii=False,
    indent=2,
    default=str,
).encode("utf-8")

json_col, pdf_col = st.columns(2)

with json_col:
    st.download_button(
        "Download JSON Report",
        data=json_bytes,
        file_name="traceweaver_investigation_report.json",
        mime="application/json",
        use_container_width=True,
        key="download_traceweaver_json",
    )
with pdf_col:
    try:
        pdf_bytes = build_investigation_pdf(report)
        st.download_button(
            "Download PDF Report",
            data=pdf_bytes,
            file_name="traceweaver_investigation_report.pdf",
            mime="application/pdf",
            use_container_width=True,
            key="download_traceweaver_pdf",
        )
    except Exception as exc:
        st.error("Could not generate the PDF report.")
        st.caption(f"{type(exc).__name__}: {exc}")
