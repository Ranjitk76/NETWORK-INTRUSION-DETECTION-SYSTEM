import sqlite3
from datetime import datetime
import time

DATABASE = "nids.db"

print("=" * 50)
print("        BASIC NIDS UDP FLOOD DATABASE TEST")
print("=" * 50)
print()

conn = sqlite3.connect(DATABASE)

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

for packet_number in range(1, 101):

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
        45000 + packet_number,
        5000,
        "UDP",
        "Possible UDP Flood",
        "MEDIUM",
        "Controlled NIDS test: very high number of UDP packets detected within 10 seconds."
    ))

    print(f"Test UDP alert inserted -> Packet {packet_number}/100")

    time.sleep(0.03)

conn.commit()
conn.close()

print()
print("=" * 50)
print("UDP FLOOD DATABASE TEST COMPLETED")
print("=" * 50)
print()
print("100 controlled UDP flood alerts inserted.")
print()
print("Open the NIDS dashboard and refresh the page.")
