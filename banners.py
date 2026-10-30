import socket

# Ports where WE must speak first (web servers wait for a request)
HTTP_PORTS = {80, 443, 5000, 7000, 8000, 8080}


def grab_banner(host, port, timeout=3):
    """Connect to an open port and return what the service says about itself."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if port in HTTP_PORTS:
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            data = s.recv(1024)
    except OSError:
        return None

    text = data.decode(errors="ignore").strip()
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return text.splitlines()[0] if text else None


if __name__ == "__main__":
    tests = [("scanme.nmap.org", 22), ("scanme.nmap.org", 80), ("127.0.0.1", 5000)]
    for host, port in tests:
        print(f"{host}:{port} -> {grab_banner(host, port)}")