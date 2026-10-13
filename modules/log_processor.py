from pathlib import Path
import json
import pandas as pd

REQUIRED_COLUMNS = ["event_id", "timestamp", "source", "event_type", "user", "device", "ip_address", "description"]
COLUMN_ALIASES = {
    "id": "event_id",
    "time": "timestamp",
    "datetime": "timestamp",
    "event": "event_type",
    "account": "user",
    "username": "user",
    "host": "device",
    "hostname": "device",
    "ip": "ip_address",
    "message": "description",
    "details": "description",
    "log_source": "source",
}

def load_sample_logs():
    sample_path = Path(__file__).resolve().parent.parent / "data" / "sample_security_logs.csv"
    return pd.read_csv(sample_path)

def normalise_logs(raw_df):
    df = raw_df.copy()
    messages = []
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    renamed = {col: COLUMN_ALIASES[col] for col in df.columns if col in COLUMN_ALIASES}
    if renamed:
        df = df.rename(columns=renamed)

    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            if col == "event_id":
                df[col] = ["EVT-{:04d}".format(i + 1) for i in range(len(df))]
                messages.append("Missing event_id column: generated temporary IDs.")
            else:
                df[col] = ""
                messages.append("Missing '{}' column: filled with blank values.".format(col))

    df["event_id"] = df["event_id"].fillna("").astype(str).str.strip()
    empty_ids = df["event_id"].eq("")
    if empty_ids.any():
        for idx in df.index[empty_ids]:
            df.loc[idx, "event_id"] = "EVT-{:04d}".format(idx + 1)

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    invalid_timestamps = int(df["timestamp"].isna().sum())
    if invalid_timestamps:
        messages.append("{} row(s) have invalid or missing timestamps and cannot be placed accurately on the timeline.".format(invalid_timestamps))

    for col in ["source", "event_type", "user", "device", "ip_address", "description"]:
        df[col] = df[col].fillna("").astype(str).str.strip()

    df = df.sort_values("timestamp", na_position="last").reset_index(drop=True)
    return df, messages

def validate_logs(df):
    if len(df) == 0:
        return False, ["The file contains no rows."]
    if df["timestamp"].isna().all():
        return False, ["No valid timestamps were found. Provide a timestamp column with parseable dates/times."]
    if df["event_type"].replace("", pd.NA).isna().all():
        return False, ["No event_type values were found. Add an event_type or event column."]
    return True, []
