import errno
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

TARGET = "scanme.nmap.org"   # Nmap's official practice server (allowed)
PORTS = range(1, 1025)       # the "well-known" ports 1-1024
THREADS = 50                 # how many ports we knock on at the same time


def scan_port(port):
    """Knock on one port. Return the result code (0 = open)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((TARGET, port))
    s.close()
    return result

def port_state(code):
    """Turn a result code into a port state."""
    if code == 0:
        return "open"
    if code == errno.ECONNREFUSED:
        return "closed"
    return "filtered"


ip = socket.gethostbyname(TARGET)
print(f"Scanning {TARGET} ({ip}) with {THREADS} threads...")
start = time.time()

with ThreadPoolExecutor(max_workers=THREADS) as executor:
    results = executor.map(scan_port, PORTS)

results = list(results)
open_ports = [port for port, code in zip(PORTS, results) if code == 0]
states = Counter(port_state(code) for code in results)
print(f"Open: {states['open']}  Closed: {states['closed']}  Filtered: {states['filtered']}")

elapsed = time.time() - start
for port in open_ports:
    print(f"Port {port} is OPEN")
print(f"\nScan finished in {elapsed:.2f} seconds")