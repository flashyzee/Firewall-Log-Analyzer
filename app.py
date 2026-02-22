import streamlit as st
from log_analyzer import analyze_logs
import tempfile

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events.")

# File uploader
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    # Save to a temporary file to pass filename to analyze_logs
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_filename = tmp_file.name

    # Run the analysis
    try:
        result = analyze_logs(tmp_filename)

        # Show raw logs
        st.subheader("Raw Logs")
        st.dataframe(result["logs"])

        # Show summary
        st.subheader("Summary")
        st.write(f"✅ Allowed entries: {result['allow_count']}")
        st.write(f"❌ Denied entries: {result['deny_count']}")

        # Show suspicious entries
        if result["suspicious"]:
            st.subheader("Suspicious Entries")
            st.dataframe(result["suspicious"])
        else:
            st.write("No suspicious entries found.")

    except Exception as e:
        st.error("Error running analysis")
        st.text(str(e))
