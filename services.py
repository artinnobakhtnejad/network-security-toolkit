import re

# Well-known ports and the service that usually runs there
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5000: "AirPlay/UPnP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 7000: "AirPlay", 8000: "HTTP-alt",
    8080: "HTTP-alt", 27017: "MongoDB",
}

# Ports that are risky just by being open
RISKY_PORTS = {
    21: "FTP sends passwords in plain text. Use SFTP instead.",
    23: "Telnet sends everything in plain text, even passwords. Use SSH instead.",
    445: "SMB is a favourite target of worms like WannaCry. Never expose it to the internet.",
    3306: "A database is reachable from the network. Databases should stay private.",
    3389: "RDP is often attacked by password guessing. Put it behind a VPN.",
    5900: "VNC often has weak or no passwords.",
    6379: "Redis often runs with no password by default.",
    27017: "Open MongoDB databases have caused many data leaks.",
}

# Simplified minimum versions for learning (real tools use CVE databases)
MIN_VERSIONS = {
    "OpenSSH": (8, 0),
    "Apache": (2, 4, 50),
}

VERSION_PATTERNS = {
    "OpenSSH": re.compile(r"OpenSSH_(\d+)\.(\d+)"),
    "Apache": re.compile(r"Apache/(\d+)\.(\d+)\.(\d+)"),
}


def service_name(port):
    """Return the usual service name for a port."""
    return COMMON_PORTS.get(port, "unknown")


def check_version(banner):
    """Return a warning if the banner shows an outdated version, else None."""
    if not banner:
        return None
    for software, pattern in VERSION_PATTERNS.items():
        match = pattern.search(banner)
        if match:
            version = tuple(int(n) for n in match.groups())
            minimum = MIN_VERSIONS[software]
            if version < minimum:
                found = ".".join(match.groups())
                needed = ".".join(str(n) for n in minimum)
                return f"{software} {found} is outdated (older than {needed})."
    return None


def warnings_for(port, banner):
    """Collect every warning for one open port."""
    warnings = []
    if port in RISKY_PORTS:
        warnings.append(RISKY_PORTS[port])
    outdated = check_version(banner)
    if outdated:
        warnings.append(outdated)
    return warnings


if __name__ == "__main__":
    tests = [
        (22, "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"),
        (22, "SSH-2.0-OpenSSH_9.6"),
        (80, "Apache/2.4.7 (Ubuntu)"),
        (23, None),
        (5000, "AirTunes/960.13.1"),
    ]
    for port, banner in tests:
        print(f"Port {port} ({service_name(port)}), banner: {banner}")
        for warning in warnings_for(port, banner):
            print(f"   WARNING: {warning}")