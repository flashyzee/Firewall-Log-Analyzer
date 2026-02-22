# app.py
import streamlit as st
import pytz 
import csv 
import subprocess
import tempfile

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events using your existing CLI script.")

# File uploader
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    # Save uploaded CSV to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_filename = tmp_file.name

    st.subheader("Terminal Output")
    st.write("Running: `python index.py --filename {}`".format(tmp_filename))

    try:
        # Run your index.py with the uploaded file
        result = subprocess.run(
            ["python", "index.py", "--filename", tmp_filename],
            capture_output=True,
            text=True,
            check=True
        )

        # Display stdout as a terminal
        st.code(result.stdout)

        # If there’s anything in stderr, display it too
        if result.stderr:
            st.subheader("Errors / Warnings")
            st.code(result.stderr)

    except subprocess.CalledProcessError as e:
        st.error("Error running index.py")
        st.code(f"Return code: {e.returncode}\n\nStdout:\n{e.stdout}\n\nStderr:\n{e.stderr}")
