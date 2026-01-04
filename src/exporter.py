import csv
from typing import Dict, Any, Tuple

from src.utils.helpers import format_timestamp

FlowKey = Tuple[str, str, str, int, int]


def export_flows_to_csv(
    flows: Dict[FlowKey, Dict[str, Any]],
    output_path: str,
) -> None:
    """
    Export flow summaries to CSV.

    CSV columns:
        src_ip,dst_ip,protocol,src_port,dst_port,packets,bytes,start_time,end_time
    """
    fieldnames = [
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "packets",
        "bytes",
        "start_time",
        "end_time",
    ]

    with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for (src_ip, dst_ip, protocol, src_port, dst_port), stats in flows.items():
            row = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "packets": stats["packet_count"],
                "bytes": stats["total_bytes"],
                "start_time": format_timestamp(stats["first_seen"]),
                "end_time": format_timestamp(stats["last_seen"]),
            }
            writer.writerow(row)
