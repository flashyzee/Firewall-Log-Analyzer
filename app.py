# app.py
import streamlit as st
import csv
import io
from log_analyzer import LogEntry

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events.")

# --------------------------
# Helper function
# --------------------------
def analyze_csv(file_bytes):
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
        rule_id = row.get("rule_id", "")

        # Count actions
        if action == "allow":
            allow_count += 1
        elif action == "deny":
            deny_count += 1

        # Suspicious countries
        if country in ["russia", "china"]:
            suspicious.append(row)

        # Determine IPv4 class using LogEntry
        try:
            log_entry = LogEntry(
                event_time=event_time,
                internal_ip=row.get("internal_ip", ""),
                port_number=row.get("port_number", "0"),
                protocol=row.get("protocol", ""),
                action=row.get("action", ""),
                rule_id=rule_id,
                source_ip=source_ip,
                country=country,
                country_name=row.get("country_name", "")
            )
            ip_class = log_entry.ipv4_class
        except Exception:
            ip_class = "Unknown"

        terminal_output.append(
            f"{event_time}, {action.title()}, {source_ip}, {rule_id}, {row.get('country_name','')}, Class {ip_class}"
        )

    return logs, allow_count, deny_count, suspicious, terminal_output

# --------------------------
# File uploader
# --------------------------
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
if uploaded_file is not None:
    file_bytes = uploaded_file.read()

    logs, allow_count, deny_count, suspicious, terminal_output = analyze_csv(file_bytes)

    # --------------------------
    # Display raw logs
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

    # --------------------------
    # Terminal simulation with first 5 preview
    # --------------------------
    st.subheader("Terminal Output (Simulated)")

    show_all = st.checkbox("Show all logs", value=False)
    output_preview = terminal_output if show_all else terminal_output[:5]

    st.code("\n".join(output_preview))
