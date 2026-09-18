from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
import time
import os
from datetime import datetime

DATABASE = "nids.db"
STATUS_FILE = "detector_status.txt"

TIME_WINDOW = 10

PORT_SCAN_THRESHOLD = 10
SYN_FLOOD_THRESHOLD = 50
ICMP_FLOOD_THRESHOLD = 50
UDP_FLOOD_THRESHOLD = 200

COOLDOWN_SECONDS = 30


# ============================================================
# ACTIVITY STORAGE
# ============================================================

port_activity = {}
syn_activity = {}
icmp_activity = {}
udp_activity = {}

last_alert_time = {}


# ============================================================
# HEARTBEAT
# ============================================================

def update_heartbeat():
    try:
        with open(STATUS_FILE, "w", encoding="utf-8") as file:
            file.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    except Exception:
        pass


# ============================================================
# DATABASE
# ============================================================

def save_alert(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    attack_type,
    severity,
    description
):

    current_time = time.time()

    cooldown_key = (source_ip, attack_type)

    if cooldown_key in last_alert_time:

        if current_time - last_alert_time[cooldown_key] < COOLDOWN_SECONDS:
            return

    last_alert_time[cooldown_key] = current_time

    try:

        conn = sqlite3.connect(DATABASE)

        conn.execute("""
            INSERT INTO alerts (
                timestamp,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                attack_type,
                severity,
                description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack_type,
            severity,
            description
        ))

        conn.commit()
        conn.close()

        print()
        print("🚨 ALERT DETECTED")
        print("Attack Type :", attack_type)
        print("Source IP   :", source_ip)
        print("Destination :", destination_ip)
        print("Protocol    :", protocol)
        print("Severity    :", severity)
        print()

    except Exception as error:
        print("Database error:", error)


# ============================================================
# MULTICAST / BROADCAST FILTER
# ============================================================

def is_multicast_or_broadcast(ip_address):

    if not ip_address:
        return True

    if ip_address.startswith("224."):
        return True

    if ip_address.startswith("239."):
        return True

    if ip_address == "255.255.255.255":
        return True

    return False


# ============================================================
# CLEANUP FUNCTIONS
# ============================================================

def cleanup_timestamp_activity(activity):

    current_time = time.time()

    for source_ip in list(activity.keys()):

        activity[source_ip] = [
            timestamp
            for timestamp in activity[source_ip]
            if current_time - timestamp <= TIME_WINDOW
        ]

        if not activity[source_ip]:
            del activity[source_ip]


def cleanup_port_activity(activity):

    current_time = time.time()

    for source_ip in list(activity.keys()):

        activity[source_ip] = [
            item
            for item in activity[source_ip]
            if current_time - item[0] <= TIME_WINDOW
        ]

        if not activity[source_ip]:
            del activity[source_ip]


# ============================================================
# PORT SCAN DETECTION
# ============================================================

def detect_port_scan(source_ip, destination_ip, destination_port):

    try:
        destination_port = int(destination_port)
    except Exception:
        return

    current_time = time.time()

    if source_ip not in port_activity:
        port_activity[source_ip] = []

    port_activity[source_ip].append(
        (current_time, destination_port)
    )

    cleanup_port_activity(port_activity)

    recent_ports = set(
        port
        for timestamp, port in port_activity.get(source_ip, [])
        if current_time - timestamp <= TIME_WINDOW
    )

    if len(recent_ports) >= PORT_SCAN_THRESHOLD:

        save_alert(
            source_ip,
            destination_ip,
            None,
            destination_port,
            "TCP",
            "Possible Port Scan",
            "HIGH",
            "Multiple destination TCP ports accessed from the same source within 10 seconds."
        )


# ============================================================
# SYN FLOOD DETECTION
# ============================================================

def detect_syn_flood(source_ip, destination_ip):

    current_time = time.time()

    if source_ip not in syn_activity:
        syn_activity[source_ip] = []

    syn_activity[source_ip].append(current_time)

    cleanup_timestamp_activity(syn_activity)

    packet_count = len(syn_activity.get(source_ip, []))

    if packet_count >= SYN_FLOOD_THRESHOLD:

        save_alert(
            source_ip,
            destination_ip,
            None,
            None,
            "TCP",
            "Possible SYN Flood",
            "HIGH",
            "High number of TCP SYN packets detected from the same source within 10 seconds."
        )


# ============================================================
# ICMP FLOOD DETECTION
# ============================================================

def detect_icmp_flood(source_ip, destination_ip):

    current_time = time.time()

    if source_ip not in icmp_activity:
        icmp_activity[source_ip] = []

    icmp_activity[source_ip].append(current_time)

    cleanup_timestamp_activity(icmp_activity)

    packet_count = len(icmp_activity.get(source_ip, []))

    if packet_count >= ICMP_FLOOD_THRESHOLD:

        save_alert(
            source_ip,
            destination_ip,
            None,
            None,
            "ICMP",
            "Possible ICMP Flood",
            "MEDIUM",
            "High number of ICMP packets detected from the same source within 10 seconds."
        )


# ============================================================
# UDP FLOOD DETECTION
# ============================================================

def detect_udp_flood(source_ip, destination_ip):

    current_time = time.time()

    if source_ip not in udp_activity:
        udp_activity[source_ip] = []

    udp_activity[source_ip].append(current_time)

    cleanup_timestamp_activity(udp_activity)

    packet_count = len(udp_activity.get(source_ip, []))

    if packet_count >= UDP_FLOOD_THRESHOLD:

        save_alert(
            source_ip,
            destination_ip,
            None,
            None,
            "UDP",
            "Possible UDP Flood",
            "MEDIUM",
            "High number of UDP packets detected from the same source within 10 seconds."
        )


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):

    try:

        update_heartbeat()

        if not packet.haslayer(IP):
            return

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        print(
            f"Packet: {source_ip} -> {destination_ip}"
        )

        # Ignore multicast and broadcast traffic
        if is_multicast_or_broadcast(destination_ip):
            return

        # --------------------------------------------
        # TCP
        # --------------------------------------------

        if packet.haslayer(TCP):

            tcp_packet = packet[TCP]

            source_port = int(tcp_packet.sport)
            destination_port = int(tcp_packet.dport)

            # SYN packet without ACK
            if tcp_packet.flags & 0x02 and not (tcp_packet.flags & 0x10):

                detect_syn_flood(
                    source_ip,
                    destination_ip
                )

            detect_port_scan(
                source_ip,
                destination_ip,
                destination_port
            )

        # --------------------------------------------
        # UDP
        # --------------------------------------------

        elif packet.haslayer(UDP):

            # Ignore common discovery traffic
            destination_port = int(packet[UDP].dport)

            discovery_ports = {
                53,
                67,
                68,
                137,
                138,
                1900,
                5353
            }

            if destination_port not in discovery_ports:

                detect_udp_flood(
                    source_ip,
                    destination_ip
                )

        # --------------------------------------------
        # ICMP
        # --------------------------------------------

        elif packet.haslayer(ICMP):

            detect_icmp_flood(
                source_ip,
                destination_ip
            )

    except Exception as error:

        print(
            "Packet processing error:",
            error
        )


# ============================================================
# START DETECTOR
# ============================================================

def start_detector():

    print("=" * 60)
    print("              BASIC NIDS DETECTOR")
    print("=" * 60)

    print()
    print("Detector Status : ONLINE")
    print("Database        :", DATABASE)
    print()
    print("Detection Settings")
    print("------------------------------")
    print("Time Window     :", TIME_WINDOW, "seconds")
    print("Port Scan       :", PORT_SCAN_THRESHOLD, "ports")
    print("SYN Flood       :", SYN_FLOOD_THRESHOLD, "packets")
    print("ICMP Flood      :", ICMP_FLOOD_THRESHOLD, "packets")
    print("UDP Flood       :", UDP_FLOOD_THRESHOLD, "packets")
    print("Cooldown        :", COOLDOWN_SECONDS, "seconds")
    print()
    print("Ignoring:")
    print("- Multicast traffic")
    print("- Broadcast traffic")
    print("- Common discovery UDP traffic")
    print()
    print("Starting packet capture...")
    print("Press CTRL+C to stop.")
    print("=" * 60)
    print()

    update_heartbeat()

    try:

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print()
        print("Detector stopped by user.")

    except Exception as error:

        print()
        print("Detector error:", error)

    finally:

        # Remove heartbeat file so dashboard shows OFFLINE
        try:
            if os.path.exists(STATUS_FILE):
                os.remove(STATUS_FILE)
        except Exception:
            pass


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    start_detector()
