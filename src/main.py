import argparse
import os

from src.pcap_reader import read_pcap
from src.flow_tracker import FlowTracker
from src.exporter import export_flows_to_csv
from src.utils.helpers import validate_pcap_path


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the PCAP traffic analyzer.

    Returns:
        argparse.Namespace containing:
            - pcap: input PCAP file path
            - export: output format (csv)
            - output: optional output file path
    """
    parser = argparse.ArgumentParser(
        description="Offline PCAP Traffic Analyzer (Flow-based summary)."
    )

    # Input PCAP file path
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to the input PCAP file.",
    )

    # Export format selection (currently only CSV supported)
    parser.add_argument(
        "--export",
        choices=["csv"],
        default="csv",
        help="Export format (currently only 'csv' is supported).",
    )

    # Optional output file path override
    parser.add_argument(
        "--output",
        help="Output file path (default: exports/traffic_summary.csv).",
    )

    return parser.parse_args()


def main() -> None:
    """
    Main execution pipeline for the PCAP Flow Analyzer.

    Pipeline stages:
        1. Parse CLI arguments
        2. Validate input PCAP file
        3. Read packets from PCAP
        4. Build flow statistics
        5. Export results to CSV
    """
    args = parse_args()

    # Validate PCAP file existence and format
    validate_pcap_path(args.pcap)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        # Default export directory and file
        os.makedirs("exports", exist_ok=True)
        output_path = os.path.join("exports", "traffic_summary.csv")

    # Initialize flow tracker for aggregating packet data into flows
    flow_tracker = FlowTracker()

    # Stream packets from PCAP into flow tracker
    for packet in read_pcap(args.pcap):
        flow_tracker.process_packet(packet)

    # Retrieve computed flow statistics
    flows = flow_tracker.get_flows()

    # Export results in the requested format
    if args.export == "csv":
        export_flows_to_csv(flows, output_path)
    else:
        # Future extension point for additional formats (e.g., JSON, SQLite)
        raise ValueError(f"Unsupported export format: {args.export}")

    # Final summary output
    print(f"[+] Exported {len(flows)} flows to: {output_path}")


if __name__ == "__main__":
    main()
