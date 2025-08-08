# TCP-SYN-FLOOD

TCP SYN Flood Attack — Detection, Analysis, and Mitigation
=========================================================

Overview
--------
This repository contains a complete proof-of-concept (PoC) implementation of a TCP SYN Flood attack along with corresponding detection and mitigation scripts.
It includes:
- Low-level TCP SYN packet crafting using Scapy
- Real-time network traffic analysis for anomaly detection
- Automated firewall rule injection for attack mitigation
- High-level algorithms describing attack, detection, and prevention logic

⚠ IMPORTANT: This project is intended strictly for cybersecurity research, penetration testing in isolated lab networks, and educational purposes. Unauthorized use on public or private networks without explicit permission is illegal.

Directory Structure
-------------------
TCP SYN FLOOD/
│
├── attack_algo.txt           # Pseudocode describing SYN flood generation logic
├── detect_algo.txt           # Pseudocode describing detection heuristics
├── prevent_algo.txt          # Pseudocode describing mitigation techniques
│
├── syn_flood_modified.py     # PoC script to generate high-volume SYN packets
├── detection_script.py       # Real-time packet sniffer + SYN anomaly detector
├── prevention_modified.py    # Automated mitigation via dynamic iptables rules

System Requirements
-------------------
- Python 3.6+ (tested on Linux)
- Root/Administrator privileges (raw sockets and firewall manipulation require elevated rights)
- Linux OS (for iptables integration in prevention script)
- Installed dependencies:
    pip install scapy

Network Requirements
--------------------
- Target host IP address (for attack simulation)
- Ability to run in a controlled network or VM environment
- Packet capture capability (tcpdump/Wireshark optional for verification)

Execution Guide
---------------
1. Launch SYN Flood Attack (PoC):
    sudo python3 syn_flood_modified.py <target_ip> <target_port>
   This crafts and sends a high volume of TCP SYN packets with spoofed source addresses.

2. Run Detection Module:
    sudo python3 detection_script.py
   Continuously sniffs packets on the default network interface, counts SYN flags per IP, and flags IPs exceeding a configurable threshold.

3. Execute Prevention/Mitigation Script:
    sudo python3 prevention_modified.py
   Dynamically injects iptables DROP rules for malicious IPs detected in real time.

Technical Workflow
------------------
1. Attack Phase:
   - Packet crafting using Scapy's IP() and TCP() layers
   - Spoofed source IP addresses to bypass basic filtering
   - Burst transmission of incomplete TCP handshakes to exhaust target resources

2. Detection Phase:
   - Real-time sniffing of inbound traffic
   - Analysis of TCP flags (SYN without ACK)
   - Threshold-based anomaly scoring (e.g., >100 SYN packets in 10 seconds from same IP)

3. Prevention Phase:
   - Identified malicious IPs are appended to a blocklist
   - iptables rules injected to drop packets from blocklisted IPs
   - Optional: Rule expiration to prevent permanent bans

Operational Notes
-----------------
- Use tcpdump or Wireshark alongside detection for verification:
    sudo tcpdump -n 'tcp[tcpflags] & tcp-syn != 0'
- Scripts are intentionally configurable for packet rate, thresholds, and logging
- Modify source code to integrate with advanced firewalls or intrusion prevention systems

Disclaimer
----------
Run ONLY in a controlled lab environment. Performing SYN Flood attacks on production networks without authorization is a criminal offense.
