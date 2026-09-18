import sqlite3
from datetime import datetime
import time

DATABASE = "nids.db"

print("=" * 50)
print("        BASIC NIDS PORT SCAN DATABASE TEST")
print("=" * 50)
print()

conn = sqlite3.connect(DATABASE)

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

for port_number in range(10000, 10015):

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
        50000,
        port_number,
        "TCP",
        "Possible Port Scan",
        "HIGH",
        "Controlled NIDS test: multiple destination TCP ports detected."
    ))

    print(
        f"Test port-scan alert inserted -> "
        f"Destination port {port_number}"
    )

    time.sleep(0.05)

conn.commit()
conn.close()

print()
print("=" * 50)
print("PORT SCAN DATABASE TEST COMPLETED")
print("=" * 50)
print()
print("15 controlled port-scan alerts inserted.")
print()
