from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import os
import json
from datetime import datetime


# Load configuration
with open("config.json", "r", encoding="utf-8") as config_file:
    config = json.load(config_file)

INTERFACE = config["interface"]

PORT_SCAN_THRESHOLD = config["port_scan"]["threshold"]
PORT_SCAN_WINDOW = config["port_scan"]["window_seconds"]

ICMP_THRESHOLD = config["icmp_flood"]["threshold"]
ICMP_WINDOW = config["icmp_flood"]["window_seconds"]

TCP_THRESHOLD = config["tcp_connections"]["threshold"]
TCP_WINDOW = config["tcp_connections"]["window_seconds"]

# Make sure the logs directory exists
os.makedirs("logs", exist_ok=True)


# Store activity for detection
port_activity = {}
connection_activity = {}
icmp_activity = {}

# Traffic statistics
packet_stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0
}


# --------------------------------------------------
# ALERT LOGGING
# --------------------------------------------------

def log_alert(alert_type, source_ip, destination_ip, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_message = (
        f"{timestamp} | "
        f"{alert_type} | "
        f"Source: {source_ip} | "
        f"Target: {destination_ip} | "
        f"{details}\n"
    )

    with open("logs/nids_alerts.log", "a", encoding="utf-8") as log_file:
        log_file.write(log_message)


# --------------------------------------------------
# PORT SCAN DETECTION
# --------------------------------------------------

def detect_port_scan(source_ip, destination_ip, destination_port):
    current_time = time.time()

    if source_ip not in port_activity:
        port_activity[source_ip] = {
            "ports": set(),
            "start_time": current_time
        }

    data = port_activity[source_ip]

    data["ports"].add(destination_port)

    elapsed_time = current_time - data["start_time"]

    # 10 different ports within 10 seconds
    if elapsed_time <= PORT_SCAN_WINDOW and len(data["ports"]) >= PORT_SCAN_THRESHOLD:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print()
        print("=" * 60)
        print("🚨 SECURITY ALERT")
        print("=" * 60)
        print("Type:            Possible Port Scan")
        print(f"Source IP:       {source_ip}")
        print(f"Target IP:       {destination_ip}")
        print(f"Ports Detected:  {len(data['ports'])}")
        print("Severity:        HIGH")
        print(f"Time:            {timestamp}")
        print("=" * 60)
        print()

        log_alert(
            "Possible Port Scan",
            source_ip,
            destination_ip,
            f"Ports Detected: {len(data['ports'])} | Severity: HIGH"
        )

        # Reset after alert
        port_activity[source_ip] = {
            "ports": set(),
            "start_time": current_time
        }


# --------------------------------------------------
# EXCESSIVE TCP CONNECTION DETECTION
# --------------------------------------------------

def detect_excessive_connections(source_ip, destination_ip):
    current_time = time.time()

    if source_ip not in connection_activity:
        connection_activity[source_ip] = {
            "count": 0,
            "start_time": current_time
        }

    data = connection_activity[source_ip]

    elapsed_time = current_time - data["start_time"]

    # Start a new 5-second window
    if elapsed_time > TCP_WINDOW:
        connection_activity[source_ip] = {
            "count": 1,
            "start_time": current_time
        }
        return

    data["count"] += 1

    # 20 TCP SYN packets within 5 seconds
    if data["count"] >= TCP_THRESHOLD:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print()
        print("=" * 60)
        print("🚨 SECURITY ALERT")
        print("=" * 60)
        print("Type:            Possible Excessive TCP Connections")
        print(f"Source IP:       {source_ip}")
        print(f"Target IP:       {destination_ip}")
        print(f"SYN Packets:     {data['count']}")
        print("Severity:        HIGH")
        print(f"Time:            {timestamp}")
        print("=" * 60)
        print()

        log_alert(
            "Possible Excessive TCP Connections",
            source_ip,
            destination_ip,
            f"SYN Packets: {data['count']} | Severity: HIGH"
        )

        # Reset after alert
        connection_activity[source_ip] = {
            "count": 0,
            "start_time": current_time
        }


# --------------------------------------------------
# ICMP FLOOD DETECTION
# --------------------------------------------------

def detect_icmp_flood(source_ip, destination_ip):
    current_time = time.time()

    if source_ip not in icmp_activity:
        icmp_activity[source_ip] = {
            "count": 1,
            "start_time": current_time
        }
        return

    data = icmp_activity[source_ip]

    elapsed_time = current_time - data["start_time"]

    # Start a new 5-second window
    if elapsed_time > ICMP_WINDOW:
        icmp_activity[source_ip] = {
            "count": 1,
            "start_time": current_time
        }
        return

    data["count"] += 1

    # 20 ICMP packets within 5 seconds
    if data["count"] >= ICMP_THRESHOLD:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print()
        print("=" * 60)
        print("🚨 SECURITY ALERT")
        print("=" * 60)
        print("Type:            Possible ICMP Flood")
        print(f"Source IP:       {source_ip}")
        print(f"Target IP:       {destination_ip}")
        print(f"ICMP Packets:    {data['count']}")
        print("Severity:        HIGH")
        print(f"Time:            {timestamp}")
        print("=" * 60)
        print()

        log_alert(
            "Possible ICMP Flood",
            source_ip,
            destination_ip,
            f"ICMP Packets: {data['count']} | Severity: HIGH"
        )

        # Reset after alert
        icmp_activity[source_ip] = {
            "count": 0,
            "start_time": current_time
        }


# --------------------------------------------------
# PACKET CALLBACK
# --------------------------------------------------

def packet_callback(packet):

    if IP not in packet:
        return

    packet_stats["total"] += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_length = len(packet)

    print(f"Source IP:        {source_ip}")
    print(f"Destination IP:   {destination_ip}")
    print(f"Packet Length:    {packet_length} bytes")

    # ---------------- TCP ----------------

    if TCP in packet:
        packet_stats["tcp"] += 1

        print("Protocol:         TCP")
        print(f"Source Port:      {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

        detect_port_scan(
            source_ip,
            destination_ip,
            packet[TCP].dport
        )

        # TCP SYN packet
        if packet[TCP].flags == "S":
            detect_excessive_connections(
                source_ip,
                destination_ip
            )

    # ---------------- UDP ----------------

    elif UDP in packet:
        packet_stats["udp"] += 1

        print("Protocol:         UDP")
        print(f"Source Port:      {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    # ---------------- ICMP ----------------

    elif ICMP in packet:
        packet_stats["icmp"] += 1

        print("Protocol:         ICMP")

        detect_icmp_flood(
            source_ip,
            destination_ip
        )

    # ---------------- OTHER ----------------

    else:
        packet_stats["other"] += 1

        print("Protocol:         Other")

    print("-" * 50)

# --------------------------------------------------
# START NIDS
# --------------------------------------------------

print("[*] NIDS detection engine started...")
print("[*] Press CTRL+C to stop.")

try:
    sniff(
        iface=INTERFACE,
        prn=packet_callback,
        store=False
    )

except KeyboardInterrupt:
    pass

finally:
    print()
    print("=" * 60)
    print("NIDS TRAFFIC SUMMARY")
    print("=" * 60)
    print(f"Total Packets:      {packet_stats['total']}")
    print(f"TCP Packets:        {packet_stats['tcp']}")
    print(f"UDP Packets:        {packet_stats['udp']}")
    print(f"ICMP Packets:       {packet_stats['icmp']}")
    print(f"Other Packets:      {packet_stats['other']}")
    print("=" * 60)
    print()
