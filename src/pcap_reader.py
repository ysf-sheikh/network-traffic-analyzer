from typing import Dict, Generator, Any

import dpkt

from src.utils.helpers import protocol_number_to_name, safe_int

def read_pcap(pcap_path: str) -> Generator[Dict[str, Any], None, None]:
"""
Parse a PCAP/PCAPNG capture file and yield normalized packet metadata.

```
Each packet is converted into a lightweight dictionary containing the
information required by downstream flow-tracking and analysis modules.

Returned packet structure:
    {
        "timestamp": float,
        "src_ip": str,
        "dst_ip": str,
        "protocol": str,
        "src_port": int,
        "dst_port": int,
        "length": int
    }

Processing rules:
    - Supports both .pcap and .pcapng formats.
    - Only IPv4 and IPv6 traffic is considered.
    - Only TCP and UDP transport protocols are processed.
    - Corrupted frames and unsupported packet types are skipped.
    - Designed for efficient streaming of packet metadata rather than
      loading an entire capture into memory.

Yields:
    Dictionary containing normalized packet metadata.
"""
with open(pcap_path, "rb") as f:
    # Select the appropriate reader based on file extension
    if pcap_path.endswith(".pcapng"):
        pcap = dpkt.pcapng.Reader(f)
    else:
        pcap = dpkt.pcap.Reader(f)

    # Iterate through packets in chronological order
    for ts, buf in pcap:
        try:
            # Decode Ethernet frame
            eth = dpkt.ethernet.Ethernet(buf)
        except (dpkt.UnpackError, ValueError):
            # Skip malformed or corrupted frames
            continue

        # Extract IP layer and ignore non-IP traffic
        ip = eth.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            continue

        # Convert source and destination addresses into
        # human-readable string representations
        src_ip = _inet_to_str(ip.src)
        dst_ip = _inet_to_str(ip.dst)

        # Resolve protocol number into a friendly protocol name
        proto_num = getattr(ip, "p", None)
        protocol_name = protocol_number_to_name(proto_num) if proto_num is not None else "UNKNOWN"

        # Extract transport-layer payload
        transport = ip.data

        # Only TCP and UDP traffic are used for flow tracking
        src_port = None
        dst_port = None

        if isinstance(transport, dpkt.tcp.TCP) or isinstance(transport, dpkt.udp.UDP):
            src_port = safe_int(getattr(transport, "sport", None))
            dst_port = safe_int(getattr(transport, "dport", None))
        else:
            # Ignore other IP protocols (ICMP, GRE, ESP, etc.)
            continue

        # Original packet size in bytes
        length = len(buf)

        # Yield normalized packet metadata
        yield {
            "timestamp": float(ts),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol_name,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
        }
```

def _inet_to_str(inet_bytes: bytes) -> str:
"""
Convert raw IP address bytes into a human-readable string.

```
Supports:
    - IPv4 addresses
    - IPv6 addresses

A hexadecimal representation is returned as a fallback if the address
cannot be decoded successfully.

Args:
    inet_bytes: Raw network-order IP address bytes.

Returns:
    String representation of the IP address.
"""
import socket

try:
    # Attempt IPv4 conversion
    return socket.inet_ntop(socket.AF_INET, inet_bytes)
except (ValueError, OSError):
    pass

try:
    # Attempt IPv6 conversion
    return socket.inet_ntop(socket.AF_INET6, inet_bytes)
except (ValueError, OSError):
    # Fallback for unexpected address formats
    return inet_bytes.hex()
