"""
Unit tests for LogEntry class.
This module validates the correctness of LogEntry behavior, including:
- Proper parsing and conversion of timestamp strings into datetime objects.
- Accurate determination of IPv4 address classes (A, B, C, D).
- Validation of network-related attributes used in log analysis.
"""
import unittest
from log_analyzer import LogEntry

class TestLogEntry(unittest.TestCase):

    def test_datetime_conversion(self) -> None:
        """
        Verify that the timestamp string is correctly converted into a datetime object.
        Ensures that the LogEntry class accurately parses the event time and extracts
        the correct month and hour values from the provided timestamp.
        """
        entry = self._make_entry("173.205.219.112")
        self.assertEqual(entry.event_time.month, 1)
        self.assertEqual(entry.event_time.hour, 8)

    def test_ipv4_class_a(self) -> None:
        """
        Confirm that a Class A IPv4 address is correctly identified.
        Tests an IP address within the Class A range and verifies that the
        ipv4_class attribute returns "A".
        """
        self.assertEqual(self._make_entry("11.22.33.44").ipv4_class, "A")

    def test_ipv4_class_b(self) -> None:
        """
        Confirm that a Class B IPv4 address is correctly identified.
        Tests an IP address within the Class B range and verifies that the
        ipv4_class attribute returns "B".
        """
        self.assertEqual(self._make_entry("150.12.1.1").ipv4_class, "B")

    def test_ipv4_class_c(self) -> None:
        """
        Confirm that a Class C IPv4 address is correctly identified.
        Tests an IP address within the Class C range and verifies that the
        ipv4_class attribute returns "C".
        """
        self.assertEqual(self._make_entry("192.168.1.1").ipv4_class, "C")

    def test_ipv4_class_d(self) -> None:
        """
        Confirm that a Class D IPv4 address is correctly identified.
        Tests an IP address within the multicast Class D range and verifies that
        the ipv4_class attribute returns "D".
        """
        self.assertEqual(self._make_entry("229.1.1.1").ipv4_class, "D")

    def _make_entry(self, ip: str) -> LogEntry:
        """
        Create and return a LogEntry instance for testing purposes. Args:
        ip (str): Destination IPv4 address used to test class detection.
        LogEntry: A fully initialized LogEntry object populated with fixed test values and the provided IP address.
        """
        return LogEntry(
            "2022-01-01 08:29:25 UTC",
            "10.0.0.1",
            "443",
            "TCP",
            "ALLOW",
            "100",
            ip,
            "US",
            "United States"
        )


if __name__ == "__main__":
    unittest.main()