import argparse
import logging
from collections import defaultdict, deque
from scapy.all import IP, TCP, sniff

SYN = 0x02
ACK = 0x10


class ScanDetector:
    """Watch SYN packets and alert when one IP knocks on too many ports."""

    def __init__(self, threshold, window):
        self.threshold = threshold
        self.window = window
        self.recent = defaultdict(deque)   # source IP -> recent knocks: (time, port)
        self.last_alert = {}               # source IP -> time of its last alert

    def check(self, packet):
        """Look at one packet and alert if its sender looks like a port scanner."""
        if IP not in packet or TCP not in packet:
            return
        flags = int(packet[TCP].flags)
        if not flags & SYN or flags & ACK:   # only knocks: SYN without ACK
            return

        src = packet[IP].src
        now = float(packet.time)
        knocks = self.recent[src]
        knocks.append((now, packet[TCP].dport))
        while knocks and now - knocks[0][0] > self.window:
            knocks.popleft()

        ports = {port for _, port in knocks}
        if len(ports) >= self.threshold and now - self.last_alert.get(src, 0) > self.window:
            self.last_alert[src] = now
            logging.warning("Possible port scan from %s: %d ports in %s s, e.g. %s",
                            src, len(ports), self.window, sorted(ports)[:10])


def main():
    parser = argparse.ArgumentParser(description="Detect TCP port scans in live or saved traffic.")
    parser.add_argument("-i", "--iface", default="lo0",
                        help="interface to watch (default: lo0, this computer)")
    parser.add_argument("--threshold", type=int, default=20,
                        help="different ports that count as a scan (default: 20)")
    parser.add_argument("--window", type=float, default=5.0,
                        help="seconds to look back (default: 5)")
    parser.add_argument("--pcap", help="analyze a saved .pcap file instead of live traffic")
    parser.add_argument("--log", default="alerts.log", help="file to save alerts in")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(args.log)],
    )

    detector = ScanDetector(args.threshold, args.window)
    if args.pcap:
        logging.info("Analyzing %s", args.pcap)
        sniff(offline=args.pcap, prn=detector.check, store=False)
    else:
        logging.info("Watching %s for port scans (%d+ ports in %s s). Ctrl+C to stop.",
                     args.iface, args.threshold, args.window)
        sniff(iface=args.iface, filter="tcp[tcpflags] & tcp-syn != 0",
              prn=detector.check, store=False)


if __name__ == "__main__":
    main()