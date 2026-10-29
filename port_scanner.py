import socket
import time

target = "127.0.0.1"   # my own Mac (localhost)


def scan_port(target, port):
    """Knock on one port. Return True if it's open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    result = s.connect_ex((target, port))
    s.close()
    return result == 0


start = time.time()
open_ports = []

for port in range(1, 10001):
    if scan_port(target, port):
        print(f"Port {port} is OPEN")
        open_ports.append(port)

elapsed = time.time() - start
print(f"\nScan finished in {elapsed:.2f} seconds")
print(f"Open ports: {open_ports}")