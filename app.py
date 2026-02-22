# app.py
import streamlit as st
import csv
import io
from log_analyzer import LogEntry
from datetime import datetime, timezone, timedelta

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events.")

# --------------------------
# Helper function to process CSV and simulate index.py output
# --------------------------
def analyze_csv(file_bytes):
    """
    Process CSV bytes, count Allow/Deny, detect suspicious entries,
    and simulate index.py terminal output.
    """
    file_text = io.TextIOWrapper(io.BytesIO(file_bytes), encoding="utf-8")
    reader = csv.DictReader(file_text)

    logs = []
    allow_count = 0
    deny_count = 0
    suspicious = []
    terminal_output = []

    for row in reader:
        logs.append(row)
        action = row.get("action", "").lower()
        country = row.get("country_name", "").lower()
        source_ip = row.get("source_ip", "")
        event_time = row.get("event_time", "")
        rule_class = row.get("rule_id", "")  # Example field

        # Count actions
        if action == "allow":
            allow_count += 1
        elif action == "deny":
            deny_count += 1

        # Suspicious countries
        if country in ["russia", "china"]:
            suspicious.append(row)

        # Simulate terminal output like index.py
        terminal_output.append(
            f"{event_time}, {action.title()}, {source_ip}, {rule_class}, {country.title()}"
        )

    return logs, allow_count, deny_count, suspicious, terminal_output

# --------------------------
# File uploader
# --------------------------
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
if uploaded_file is not None:
    file_bytes = uploaded_file.read()

    # Run analysis
    logs, allow_count, deny_count, suspicious, terminal_output = analyze_csv(file_bytes)

    # --------------------------
    # Display sections
    # --------------------------
    st.subheader("Raw Logs")
    st.dataframe(logs)

    st.subheader("Summary")
    st.write(f"✅ Allowed entries: {allow_count}")
    st.write(f"❌ Denied entries: {deny_count}")

    st.subheader("Suspicious Entries")
    if suspicious:
        st.dataframe(suspicious)
    else:
        st.write("No suspicious entries found.")

    st.subheader("Terminal Output (Simulated)")
    st.code("\n".join(terminal_output))
