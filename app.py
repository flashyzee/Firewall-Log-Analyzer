# app.py
import streamlit as st
import tempfile
import subprocess
import shlex

st.set_page_config(page_title="Firewall Log Analyzer", page_icon="🛡️")
st.title("Firewall Log Analyzer")
st.write("Upload a firewall CSV log and run `index.py` CLI simulation.")

# --------------------------
# File uploader
# --------------------------
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    # Save uploaded file to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_filename = tmp_file.name

    st.success(f"File saved to temporary path: {tmp_filename}")

    # --------------------------
    # Terminal simulation
    # --------------------------
    st.subheader("Run CLI Command (Terminal Simulation)")
    default_cmd = f"python index.py --filename {tmp_filename}"
    command = st.text_input("Enter command", default_cmd)

    if st.button("Run Command"):
        args = shlex.split(command)
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=True
            )

            # Split stdout lines
            lines = result.stdout.strip().splitlines()

            # Show first 5 lines initially
            st.subheader("Terminal Output (Preview: first 5 lines)")
            preview = lines[:5]
            st.code("\n".join(preview))

            # Option to show all
            if len(lines) > 5:
                if st.checkbox("Show all output"):
                    st.subheader("Full Terminal Output")
                    st.code("\n".join(lines))

            # Show stderr if any
            if result.stderr:
                st.subheader("Errors / Warnings")
                st.code(result.stderr)

        except subprocess.CalledProcessError as e:
            st.error("Error running command")
            st.code(f"Return code: {e.returncode}\n\nStdout:\n{e.stdout}\n\nStderr:\n{e.stderr}")
