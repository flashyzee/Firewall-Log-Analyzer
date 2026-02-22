import streamlit as st
import subprocess
import tempfile

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log to analyze access events using your existing script.")

# File uploader
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    st.success(f"File uploaded: {uploaded_file.name}")

    # Save uploaded file to a temporary location
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_filename = tmp_file.name

    # Run your existing index.py script with --filename
    try:
        result = subprocess.run(
            ["python", "index.py", "--filename", tmp_filename],
            capture_output=True,
            text=True,
            check=True
        )
        st.subheader("Output from index.py")
        st.text(result.stdout)

    except subprocess.CalledProcessError as e:
        st.error("Error running index.py")
        st.text(e.stderr)
