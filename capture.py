from scapy.all import sniff, wrpcap

FILENAME = "scan_capture.pcap"

print("Capturing SYN packets for up to 30 seconds... run a scan now!")
packets = sniff(filter="tcp[tcpflags] & tcp-syn != 0", count=50, timeout=30)

wrpcap(FILENAME, packets)
print(f"Saved {len(packets)} packets to {FILENAME}")