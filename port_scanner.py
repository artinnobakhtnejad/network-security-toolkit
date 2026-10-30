import argparse
import errno
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from banners import grab_banner
from services import service_name, warnings_for


def scan_port(target, port, timeout):
    """Knock on one port. Return the result code (0 = open)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target, port))
    s.close()
    return result


def port_state(code):
    """Turn a result code into a port state."""
    if code == 0:
        return "open"
    if code == errno.ECONNREFUSED:
        return "closed"
    return "filtered"


def parse_ports(text):
    """Turn "20-80" into range(20, 81), or "22" into range(22, 23)."""
    if "-" in text:
        start, end = text.split("-")
        start, end = int(start), int(end)
    else:
        start = end = int(text)
    if not 1 <= start <= end <= 65535:
        raise argparse.ArgumentTypeError("ports must be 1-65535, written low-high")
    return range(start, end + 1)


def main():
    parser = argparse.ArgumentParser(description="A simple multithreaded TCP port scanner.")
    parser.add_argument("target", nargs="?", default="127.0.0.1",
                        help="host to scan (default: 127.0.0.1, this computer)")
    parser.add_argument("-p", "--ports", type=parse_ports, default="1-1024",
                        help="port or range, e.g. 22 or 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                        help="ports to scan at the same time (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="seconds to wait for each port (default: 1.0)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        parser.error(f"cannot find host '{args.target}' (check the spelling)")
    print(f"Scanning {args.target} ({ip}), ports {args.ports.start}-{args.ports.stop - 1}, "
          f"{args.threads} threads...")
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(lambda port: scan_port(ip, port, args.timeout), args.ports))

    elapsed = time.time() - start
    open_ports = [port for port, code in zip(args.ports, results) if code == 0]
    if open_ports:
        print(f"\n{'PORT':<8}{'SERVICE':<15}BANNER")
    for port in open_ports:
        banner = grab_banner(args.target, port)
        print(f"{port:<8}{service_name(port):<15}{banner or '-'}")
        for warning in warnings_for(port, banner):
            print(f"{'':<8}WARNING: {warning}")

    states = Counter(port_state(code) for code in results)
    print(f"\nOpen: {states['open']}  Closed: {states['closed']}  Filtered: {states['filtered']}")
    print(f"Scan finished in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()