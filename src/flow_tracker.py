from typing import Dict, Any, Tuple


FlowKey = Tuple[str, str, str, int, int]


class FlowTracker:
    """
    Track flows and basic statistics for each flow.

    Flow key:
        (src_ip, dst_ip, protocol, src_port, dst_port)

    Stored per-flow statistics:
        - packet_count
        - total_bytes
        - first_seen
        - last_seen
    """

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, Dict[str, Any]] = {}

    def process_packet(self, packet: Dict[str, Any]) -> None:
        """
        Consume a packet metadata dict and update the corresponding flow.

        Expected packet fields:
            - timestamp: float
            - src_ip: str
            - dst_ip: str
            - protocol: str
            - src_port: int
            - dst_port: int
            - length: int
        """
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        protocol = packet["protocol"]
        src_port = int(packet["src_port"])
        dst_port = int(packet["dst_port"])
        length = int(packet["length"])
        timestamp = float(packet["timestamp"])

        key: FlowKey = (src_ip, dst_ip, protocol, src_port, dst_port)

        if key not in self._flows:
            # Initialize a new flow entry
            self._flows[key] = {
                "packet_count": 1,
                "total_bytes": length,
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        else:
            flow = self._flows[key]
            flow["packet_count"] += 1
            flow["total_bytes"] += length
            # Update timestamps
            if timestamp < flow["first_seen"]:
                flow["first_seen"] = timestamp
            if timestamp > flow["last_seen"]:
                flow["last_seen"] = timestamp

    def get_flows(self) -> Dict[FlowKey, Dict[str, Any]]:
        """
        Return the internal flow dictionary.

        Caller can iterate or transform for export.
        """
        return self._flows
