# Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System that captures network
traffic using Scapy and detects common suspicious activity in real time.

## Features

- Real-time packet capture
- TCP, UDP and ICMP traffic analysis
- Port scan detection
- ICMP flood detection
- Excessive TCP connection detection
- Security alerts in the terminal
- Alert logging to a file
- Configurable detection thresholds
- Traffic statistics summary

## Project Structure

```text
NIDS/
├── packet_sniffer.py
├── config.json
├── requirements.txt
├── .gitignore
├── README.md
├── logs/
│   └── nids_alerts.log
└── venv/

The venv/ directory and runtime log files are excluded from Git using
.gitignore.

Technologies Used
Python 3
Scapy
Linux
Network packet analysis
How It Works
Network Traffic
       ↓
Packet Capture
       ↓
Packet Analysis
       ↓
Detection Engine
       ↓
Security Alert
       ↓
Log File
Detection Rules
Port Scan Detection

The system monitors destination ports contacted by the same source IP.

Default configuration:

10 different ports
within 10 seconds
Severity: HIGH
ICMP Flood Detection

The system counts ICMP packets from the same source IP.

Default configuration:

20 ICMP packets
within 5 seconds
Severity: HIGH
Excessive TCP Connections

The system monitors TCP SYN packets from the same source IP.

Default configuration:

20 SYN packets
within 5 seconds
Severity: HIGH
Configuration

Detection thresholds are stored in config.json.

Example:

{
    "interface": "wlan0",

    "port_scan": {
        "threshold": 10,
        "window_seconds": 10
    },

    "icmp_flood": {
        "threshold": 20,
        "window_seconds": 5
    },

    "tcp_connections": {
        "threshold": 20,
        "window_seconds": 5
    }
}

This allows detection thresholds to be changed without modifying the
detection logic.

Installation

Clone the project:

git clone https://github.com/KUMAWAT2005/NIDS
cd NIDS

Create a virtual environment:

python3 -m venv venv

Activate it:

source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Create the log directory:

mkdir -p logs
touch logs/nids_alerts.log
Running the NIDS

The packet capture requires appropriate privileges:

sudo ./venv/bin/python packet_sniffer.py

The network interface is configured in config.json.

Example:

"interface": "wlan0"

Press CTRL+C to stop the NIDS and display the traffic summary.

Example Security Alert
============================================================
🚨 SECURITY ALERT
============================================================
Type:            Possible ICMP Flood
Source IP:       192.168.1.7
Target IP:       8.8.8.8
ICMP Packets:    20
Severity:        HIGH
Time:            2026-10-07 21:27:33
============================================================
Alert Logging

Alerts are stored in:

logs/nids_alerts.log

Example:

2026-10-07 21:27:33 | Possible ICMP Flood | Source: 192.168.1.7 | Target: 8.8.8.8 | ICMP Packets: 20 | Severity: HIGH
Traffic Statistics

When the NIDS is stopped, it displays a summary:

============================================================
NIDS TRAFFIC SUMMARY
============================================================
Total Packets:      100
TCP Packets:        60
UDP Packets:        30
ICMP Packets:       10
Other Packets:       0
============================================================

The actual values depend on the traffic captured during the session.

Testing

The detection functions were tested in a controlled environment.

Tested components:

Packet capture
ICMP flood detection
Port scan detection
Excessive TCP connection detection
Alert logging
Configuration loading
Traffic statistics

Testing should only be performed on systems and networks that you own or
are explicitly authorized to monitor.

Limitations

This is an educational NIDS project.

Detection thresholds are rule-based.
It does not replace a production enterprise IDS.
It currently focuses on a limited set of traffic patterns.
Detection quality depends on the traffic visible on the monitored interface.
Future Improvements

Possible future improvements include:

Web-based monitoring dashboard
More detection rules
Alert severity levels
Automatic report generation
Database-based alert storage
Unit tests
Improved packet filtering
Email or notification integration
Author

Ritesh Kumawat

Cybersecurity / Network Security Project
