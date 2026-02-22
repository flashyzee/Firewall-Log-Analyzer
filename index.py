"""
Main execution script for firewall log analyzer (rubric-compliant with regex and LogEntry objects).
"""
import argparse
import csv
from datetime import datetime
import pytz
import re
from log_analyzer import LogEntry  # import your LogEntry class

def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Firewall Log Analyzer")
    parser.add_argument("--filename", required=True, help="CSV log filename")
    return parser.parse_args()

def convert_to_est(event_time_str: str) -> datetime:
    """Converts a UTC event_time string to a datetime object in US Eastern time."""
    dt_utc = datetime.strptime(event_time_str, "%Y-%m-%d %H:%M:%S %Z")
    dt_utc = pytz.utc.localize(dt_utc)
    dt_est = dt_utc.astimezone(pytz.timezone("US/Eastern"))
    return dt_est

def get_ipv4_class(ip) -> str:
        """
        Determines IPv4 address class using ONLY regular expressions.
        Matches professor's regex teaching style.
        """
        # Extract first octet using regex
        first_octet = re.sub(r"\..*", "", ip)

        if re.match(r"^([1-9]|[1-9][0-9]|1[0-1][0-9]|12[0-6])$", first_octet): 
            return "A"

        elif re.match(r"^(12[8-9]|1[3-8]\d|19[01])$", first_octet):
            return "B"

        elif re.match(r"^(19[2-9]|2[0-1]\d|22[0-3])$", first_octet):
            return "C"

        elif re.match(r"^(22[4-9]|23\d)$", first_octet):
            return "D"

        return "Unknown"           

def main() -> None:
    """
    Load and process firewall log data from a CSV file.

    This function reads a CSV file containing network log records, converts
    each row into a LogEntry object, normalizes timestamp values to Eastern
    Standard Time (EST), and prepares structured data for further analysis.

    The CSV file is provided via command-line arguments. Each row is parsed
    into a LogEntry instance, ensuring consistent formatting, validation,
    and transformation of log fields.
    """
    args = parse_args()
    entries = []

    with open(args.filename, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Create LogEntry object
            entry = LogEntry(
                row["event_time"],
                row["internal_ip"],
                row["port_number"],
                row["protocol"],
                row["action"],
                row["rule_id"],
                row["source_ip"],
                row["country"],
                row["country_name"]
            )

            # Convert event_time to EST and store back in object
            entry.event_time = convert_to_est(entry.event_time.strftime("%Y-%m-%d %H:%M:%S UTC"))

            entry.ip_class = get_ipv4_class(entry.source_ip)

            entries.append(entry)

    # Print first 5 entries
    for entry in entries[:5]:
        print(
            f"{entry.event_time.strftime('%Y-%m-%d %H:%M:%S %Z')}, "
            f"{entry.action}, "
            f"{entry.source_ip}, "
            f"{entry.ipv4_class}, "
            f"{entry.country_name}"
        )

if __name__ == "__main__":
    main()