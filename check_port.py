import socket

target = "127.0.0.1"   # my own Mac (localhost)
port = 8000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
result = s.connect_ex((target, port))
s.close()

if result == 0:
    print(f"Port {port} is OPEN")
else:
    print(f"Port {port} is CLOSED (code {result})")