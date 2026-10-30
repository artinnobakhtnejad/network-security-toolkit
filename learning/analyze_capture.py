from collections import defaultdict
from scapy.all import IP, TCP, rdpcap

FILENAME = "scan_capture.pcap"
SYN = 0x02   # the SYN bit in the TCP flags
ACK = 0x10   # the ACK bit in the TCP flags

packets = rdpcap(FILENAME)
print(f"Loaded {len(packets)} packets from {FILENAME}\n")

# For each (source, destination) pair, collect the ports it knocked on
ports_by_pair = defaultdict(set)

for packet in packets:
    if IP in packet and TCP in packet:
        flags = int(packet[TCP].flags)
        if flags & SYN and not flags & ACK:   # a "knock": SYN without ACK
            pair = (packet[IP].src, packet[IP].dst)
            ports_by_pair[pair].add(packet[TCP].dport)

for (src, dst), ports in ports_by_pair.items():
    print(f"{src} -> {dst}: SYNs to {len(ports)} different ports")
    print(f"   first ports: {sorted(ports)[:15]}")