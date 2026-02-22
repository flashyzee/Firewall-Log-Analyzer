# app.py (fixed for terminal simulation)
import streamlit as st
import csv
import io
import tempfile
import subprocess
import pytz 
import shlex
from log_analyzer import LogEntry

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events.")

# --------------------------
# Helper function to process CSV
# --------------------------
def process_firewall_csv(file_bytes):
    file_text = io.TextIOWrapper(io.BytesIO(file_bytes), encoding="utf-8")
    reader = csv.DictReader(file_text)

    logs = []
    allow_count = 0
    deny_count = 0
    suspicious = []

    for row in reader:
        logs.append(row)
        action = row.get("action", "").lower()
        country = row.get("country_name", "").lower()

        if action == "allow":
            allow_count += 1
        elif action == "deny":
            deny_count += 1

        if country in ["russia", "china"]:
            suspicious.append(row)

    return logs, allow_count, deny_count, suspicious

# --------------------------
# File uploader
# --------------------------
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
if uploaded_file is not None:
    # Read uploaded file bytes once
    file_bytes = uploaded_file.read()

    # --------------------------
    # Process CSV for summary
    # --------------------------
    logs, allow_count, deny_count, suspicious = process_firewall_csv(file_bytes)

    # Display raw logs
    st.subheader("Raw Logs")
    st.dataframe(logs)

    # Display summary
    st.subheader("Summary")
    st.write(f"✅ Allowed entries: {allow_count}")
    st.write(f"❌ Denied entries: {deny_count}")

    # Display suspicious entries
    st.subheader("Suspicious Entries")
    if suspicious:
        st.dataframe(suspicious)
    else:
        st.write("No suspicious entries found.")

    # --------------------------
    # Terminal simulation
    # --------------------------
    st.subheader("Run CLI Command (Terminal Simulation)")
    default_cmd = "python index.py --filename uploaded_file.csv"
    command = st.text_input("Enter command", default_cmd)

    if st.button("Run Command"):
        # Write bytes to a temporary file for subprocess
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp_file:
            tmp_file.write(file_bytes)
            tmp_filename = tmp_file.name

        # Replace placeholder with actual temp file path
        cmd_to_run = command.replace("uploaded_file.csv", tmp_filename)
        args = shlex.split(cmd_to_run)

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=True
            )
            st.code(result.stdout)
            if result.stderr:
                st.subheader("Errors / Warnings")
                st.code(result.stderr)
        except subprocess.CalledProcessError as e:
            st.error("Error running command")
            st.code(f"Return code: {e.returncode}\n\nStdout:\n{e.stdout}\n\nStderr:\n{e.stderr}")
