import pandas as pd
from modules.log_processor import normalise_logs, validate_logs
from modules.correlation import build_event_relationships

def test_normalise_logs_adds_missing_columns():
    raw = pd.DataFrame([{"time": "2026-01-01T10:00:00Z", "event": "login"}])
    df, messages = normalise_logs(raw)
    assert "event_id" in df.columns
    assert "timestamp" in df.columns
    assert len(df) == 1

def test_validation_rejects_empty_data():
    df, _ = normalise_logs(pd.DataFrame(columns=["timestamp", "event_type"]))
    ok, details = validate_logs(df)
    assert not ok
    assert details

def test_relationships_use_shared_identifiers():
    raw = pd.DataFrame([
        {"event_id":"A","timestamp":"2026-01-01T10:00:00Z","source":"auth","event_type":"login","user":"sam","device":"pc1","ip_address":"198.51.100.1","description":"login"},
        {"event_id":"B","timestamp":"2026-01-01T10:05:00Z","source":"audit","event_type":"change","user":"sam","device":"pc1","ip_address":"198.51.100.1","description":"change"},
    ])
    df, _ = normalise_logs(raw)
    links = build_event_relationships(df)
    assert len(links) == 1
    assert "same user" in links[0]["shared_signals"]
