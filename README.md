# Firewall Log Analyzer
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Python tool for parsing and analyzing firewall logs to identify potential security risks and generate actionable reports.

---

## 🚀 Features

- Reads firewall logs in CSV format  
- Detects suspicious or conflicting entries  
- Generates simple summary reports  
- Includes unit tests to ensure reliability  
- Type-hinted Python code with input validation for predictable behavior  

---

## 💻 Tech Stack

- **Language:** Python 3.10+  
- **Libraries:** Only Python standard library (`csv`, `re`, `argparse`,  `pytz`, `unittest`)  
- **Testing:** `unittest`  
- **Data Handling:** CSV  

---

## 📂 Project Structure
```
firewall-log-analyzer/
├── log_analyzer.py # Core log parsing and analysis logic
├── index.py # Main script / entry point
├── test_log_analyzer.py # Unit tests
├── firewall_logs_sample.csv # Sample firewall log for testing
├── README.md
```
---

## ⚡ Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/firewall-log-analyzer.git
cd firewall-log-analyzer

2. Make sure you have Python 3.10+ installed—no additional packages are required.

🛠 Usage

Run the main script with the sample firewall log CSV: python index.py --filename firewall_logs_sample.csv

Optional flags:
python index.py --filename → Path to the firewall log CSV file

The script will analyze the logs and output a report printed directly to your console. 

🎯 Example Output
| Timestamp           | Source IP   | Destination IP | Action | Status   |
| ------------------- | ----------- | -------------- | ------ | -------- |
| 2026-02-20 12:01:00 | 192.168.1.2 | 10.0.0.5       | ALLOW  | OK       |
| 2026-02-20 12:02:00 | 192.168.1.2 | 10.0.0.5       | DENY   | Conflict |

Live Demo: https://firewall-log-analyzer.streamlit.app
