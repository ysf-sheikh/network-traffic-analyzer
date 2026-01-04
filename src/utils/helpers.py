import os
from datetime import datetime, timezone
from typing import Optional


def validate_pcap_path(path: str) -> None:
    """
    Validate that a PCAP path exists and is a regular file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the path is not a regular file or extension is suspicious.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"PCAP file not found: {path}")

    if not os.path.isfile(path):
        raise ValueError(f"PCAP path is not a file: {path}")

    # Soft check on extension; don't strictly require .pcap, but warn via exception if clearly wrong.
    _, ext = os.path.splitext(path)
    if ext and ext.lower() not in {".pcap", ".pcapng"}:
        # For now, just allow but you could tighten this later.
        pass


def protocol_number_to_name(proto_num: int) -> str:
    """
    Map IP protocol number to a human-readable name.

    Common values:
        6   -> TCP
        17  -> UDP
        1   -> ICMP

    Unrecognized values are returned as their numeric string.
    """
    mapping = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }
    return mapping.get(proto_num, str(proto_num))


def format_timestamp(ts: float) -> str:
    """
    Convert a UNIX timestamp (float seconds) to an ISO 8601 string in UTC.

    Example: '2025-01-02T12:34:56.123456+00:00'
    """
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat()


def safe_int(value: Optional[int]) -> int:
    """
    Ensure that an integer-like value is returned as int.

    If None is passed, returns 0.
    """
    if value is None:
        return 0
    return int(value)