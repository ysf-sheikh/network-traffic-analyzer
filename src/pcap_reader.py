from typing import Dict, Generator, Any

import dpkt

from src.utils.helpers import protocol_number_to_name, safe_int


def read_pcap(pcap_path: str) -> Generator[Dict[str, Any], None, None]:
    """
    Read a PCAP file and yield packet metadata dictionaries.

    Each yielded dictionary has the form:
        {
            "timestamp": float,
            "src_ip": str,
            "dst_ip": str,
            "protocol": str,
            "src_port": int,
            "dst_port": int,
            "length": int
        }

    Notes:
        - Only IP (IPv4/IPv6) + TCP/UDP packets are considered.
        - Non-IP and non-TCP/UDP packets are skipped.
    """
    with open(pcap_path, "rb") as f:
        if pcap_path.endswith(".pcapng"):
            pcap = dpkt.pcapng.Reader(f)
        else:
            pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.UnpackError, ValueError):
                # Corrupted frame; skip safely
                continue

            # Filter non-IP traffic
            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            src_ip = _inet_to_str(ip.src)
            dst_ip = _inet_to_str(ip.dst)
            proto_num = getattr(ip, "p", None)
            protocol_name = protocol_number_to_name(proto_num) if proto_num is not None else "UNKNOWN"

            transport = ip.data

            # Only consider TCP/UDP for flow tracking in this phase
            src_port = None
            dst_port = None

            if isinstance(transport, dpkt.tcp.TCP) or isinstance(transport, dpkt.udp.UDP):
                src_port = safe_int(getattr(transport, "sport", None))
                dst_port = safe_int(getattr(transport, "dport", None))
            else:
                # Non-TCP/UDP IP traffic not considered in this initial phase
                continue

            length = len(buf)

            yield {
                "timestamp": float(ts),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length,
            }


def _inet_to_str(inet_bytes: bytes) -> str:
    """
    Convert an IP address from bytes to string (supports IPv4 and IPv6).

    This avoids importing socket in top-level for readability, but you could
    move this to helpers if you want broader reuse.
    """
    import socket

    try:
        # Try IPv4
        return socket.inet_ntop(socket.AF_INET, inet_bytes)
    except (ValueError, OSError):
        pass

    try:
        # Try IPv6
        return socket.inet_ntop(socket.AF_INET6, inet_bytes)
    except (ValueError, OSError):
        # Fallback: hex representation if something odd happens
        return inet_bytes.hex()
