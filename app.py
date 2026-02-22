import streamlit as st
import csv

# --- Page setup ---
st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events.")

# --- File upload ---
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    st.success(f"File uploaded: {uploaded_file.name}")
    
    # Read CSV
    uploaded_file.seek(0)
    reader = csv.reader(uploaded_file)
    logs = list(reader)

    # Display raw logs
    st.subheader("Raw Logs")
    st.dataframe(logs)

    # --- Simple analysis ---
    allow_count = sum(1 for row in logs if row[1].lower() == "allow")
    deny_count = sum(1 for row in logs if row[1].lower() == "deny")

    st.subheader("Summary")
    st.write(f"✅ Allowed entries: {allow_count}")
    st.write(f"❌ Denied entries: {deny_count}")

    # Show suspicious countries (example)
    suspicious = [row for row in logs if row[4].lower() in ["russia", "china"]]
    if suspicious:
        st.subheader("Suspicious Entries")
        st.dataframe(suspicious)
    else:
        st.write("No suspicious entries found.")
