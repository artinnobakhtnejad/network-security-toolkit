from scapy.all import IP, TCP, UDP, sniff


def show(packet):
    """Print the source, destination, protocol and TCP flags of a packet."""
    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst

    if TCP in packet:
        tcp = packet[TCP]
        print(f"TCP  {src}:{tcp.sport} -> {dst}:{tcp.dport}  flags={tcp.flags}")
    elif UDP in packet:
        udp = packet[UDP]
        print(f"UDP  {src}:{udp.sport} -> {dst}:{udp.dport}")
    else:
        print(f"IP   {src} -> {dst}  protocol={packet[IP].proto}")


sniff(count=20, prn=show, store=False,
      filter="udp port 53 or (tcp[tcpflags] & tcp-syn != 0)")