from typing import Dict, Any, Tuple

# Unique identifier for a network flow:

# (source IP, destination IP, protocol, source port, destination port)

FlowKey = Tuple[str, str, str, int, int]

class FlowTracker:
"""
Lightweight flow tracking engine for network traffic analysis.

```
A flow is uniquely identified by the 5-tuple:
    (src_ip, dst_ip, protocol, src_port, dst_port)

For each flow, the tracker maintains:
    - packet_count : Total number of packets observed
    - total_bytes  : Total payload size across all packets
    - first_seen   : Timestamp of the first observed packet
    - last_seen    : Timestamp of the most recent packet

This class is designed for real-time packet processing and can be
used as a foundation for intrusion detection, traffic monitoring,
or network analytics applications.
"""

def __init__(self) -> None:
    # Internal flow table:
    # Key   -> FlowKey
    # Value -> Flow statistics dictionary
    self._flows: Dict[FlowKey, Dict[str, Any]] = {}

def process_packet(self, packet: Dict[str, Any]) -> None:
    """
    Process a packet metadata dictionary and update the corresponding flow.

    Expected packet structure:
        {
            "timestamp": float,
            "src_ip": str,
            "dst_ip": str,
            "protocol": str,
            "src_port": int,
            "dst_port": int,
            "length": int
        }

    If the flow does not already exist, a new entry is created.
    Otherwise, the existing flow statistics are updated.
    """
    # Extract packet metadata
    src_ip = packet["src_ip"]
    dst_ip = packet["dst_ip"]
    protocol = packet["protocol"]
    src_port = int(packet["src_port"])
    dst_port = int(packet["dst_port"])
    length = int(packet["length"])
    timestamp = float(packet["timestamp"])

    # Construct the unique flow identifier
    key: FlowKey = (src_ip, dst_ip, protocol, src_port, dst_port)

    if key not in self._flows:
        # Create a new flow record using the current packet
        self._flows[key] = {
            "packet_count": 1,
            "total_bytes": length,
            "first_seen": timestamp,
            "last_seen": timestamp,
        }
    else:
        # Update statistics for an existing flow
        flow = self._flows[key]

        # Increment packet counter
        flow["packet_count"] += 1

        # Accumulate total byte count
        flow["total_bytes"] += length

        # Maintain the earliest observed timestamp
        if timestamp < flow["first_seen"]:
            flow["first_seen"] = timestamp

        # Maintain the latest observed timestamp
        if timestamp > flow["last_seen"]:
            flow["last_seen"] = timestamp

def get_flows(self) -> Dict[FlowKey, Dict[str, Any]]:
    """
    Return the complete flow table.

    Returns:
        Dictionary mapping FlowKey objects to their
        associated statistics.

    The returned structure can be used for:
        - Reporting
        - Exporting to JSON/CSV
        - Feature extraction
        - IDS/IPS analysis pipelines
    """
    return self._flows
```
