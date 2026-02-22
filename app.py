import streamlit as st
import csv
import pytz 
import io
from datetime import datetime, timezone, timedelta

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events.")

# --------------------------
# Helper function to process CSV
# --------------------------
def process_firewall_csv(uploaded_file):
    uploaded_file.seek(0)
    file_text = io.TextIOWrapper(uploaded_file, encoding="utf-8")
    reader = csv.reader(file_text)
    
    logs = []
    allow_count = 0
    deny_count = 0
    suspicious = []

    for row in reader:
        logs.append(row)
        if row[1].lower() == "allow":
            allow_count += 1
        elif row[1].lower() == "deny":
            deny_count += 1
        if row[4].lower() in ["russia", "china"]:
            suspicious.append(row)
    
    return logs, allow_count, deny_count, suspicious

# --------------------------
# File uploader
# --------------------------
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
if uploaded_file is not None:
    logs, allow_count, deny_count, suspicious = process_firewall_csv(uploaded_file)

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
