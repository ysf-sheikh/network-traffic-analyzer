# PCAP Traffic Analyzer

This project provides a **clean, structured foundation** for analyzing offline PCAP files.
In this project, the focus is on:

- Correctly reading PCAP files
- Extracting relevant packet metadata
- Aggregating packets into flows
- Exporting flow summaries to CSV

No attack detection or deep inspection is performed yet.

---

## Features (V.1 Scope)

- Input: A single `.pcap` file
- Output: Flow-based summary in CSV format
- Flow key:
  - `src_ip`
  - `dst_ip`
  - `protocol`
  - `src_port`
  - `dst_port`
- Flow statistics:
  - `packets`
  - `bytes`
  - `start_time`
  - `end_time`

Example CSV row:

```text
src_ip,dst_ip,protocol,src_port,dst_port,packets,bytes,start_time,end_time
192.168.1.10,93.184.216.34,TCP,52345,80,12,8410,2025-01-02T12:34:56.123456+00:00,2025-01-02T12:35:10.654321+00:00
