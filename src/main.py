import argparse
import os

from src.pcap_reader import read_pcap
from src.flow_tracker import FlowTracker
from src.exporter import export_flows_to_csv
from src.utils.helpers import validate_pcap_path

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline PCAP Traffic Analyzer (Flow-based summary)."
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to the input PCAP file.",
    )
    parser.add_argument(
        "--export",
        choices=["csv"],
        default="csv",
        help="Export format (currently only 'csv' is supported).",
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: exports/traffic_summary.csv).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Validation and default handling kept here, but no analysis logic.
    validate_pcap_path(args.pcap)

    if args.output:
        output_path = args.output
    else:
        # Default output path
        os.makedirs("exports", exist_ok=True)
        output_path = os.path.join("exports", "traffic_summary.csv")

    # Orchestration: read packets, track flows, export
    flow_tracker = FlowTracker()

    for packet in read_pcap(args.pcap):
        flow_tracker.process_packet(packet)

    flows = flow_tracker.get_flows()

    if args.export == "csv":
        export_flows_to_csv(flows, output_path)
    else:
        # This branch is mostly future-proofing; for now, only CSV is allowed by argparse.
        raise ValueError(f"Unsupported export format: {args.export}")

    print(f"[+] Exported {len(flows)} flows to: {output_path}")


if __name__ == "__main__":
    main()
