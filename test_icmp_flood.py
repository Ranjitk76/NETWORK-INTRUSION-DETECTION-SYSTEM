import sqlite3
from datetime import datetime
import time

DATABASE = "nids.db"

print("=" * 50)
print("        BASIC NIDS ICMP FLOOD DATABASE TEST")
print("=" * 50)
print()

conn = sqlite3.connect(DATABASE)

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

for packet_number in range(1, 56):

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
        now,
        "172.17.7.173",
        "172.17.7.173",
        None,
        None,
        "ICMP",
        "Possible ICMP Flood",
        "MEDIUM",
        "Controlled NIDS test: high number of ICMP packets detected within 10 seconds."
    ))

    print(f"Test ICMP alert inserted -> Packet {packet_number}/55")

    time.sleep(0.05)

conn.commit()
conn.close()

print()
print("=" * 50)
print("ICMP FLOOD DATABASE TEST COMPLETED")
print("=" * 50)
print()
print("55 controlled ICMP flood alerts inserted.")
print()
print("Open the NIDS dashboard and refresh the page.")
