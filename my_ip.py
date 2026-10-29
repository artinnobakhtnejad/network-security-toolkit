import socket

# 1. Get my computer's name on the network
hostname = socket.gethostname()
print("My computer's name:", hostname)

# 2. Find the IP address my computer uses on my home network
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
local_ip = s.getsockname()[0]
s.close()
print("My local IP address:", local_ip)