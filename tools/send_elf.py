#!/usr/bin/env python3
"""Send an ELF to a PS5's public elfldr and print what the console says.

elfldr listens on 127.0.0.1:9021 from the console's own point of view, so from
a PC you connect to the console's LAN address instead.

    usage: send_elf.py <elf> <console-ip> [port]
"""
import socket
import sys
import time

if len(sys.argv) < 3:
    sys.exit("usage: send_elf.py <elf> <console-ip> [port]")

path = sys.argv[1]
host = sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) > 3 else 9021

with open(path, "rb") as handle:
    data = handle.read()

print("sending %s (%d bytes) to %s:%d" % (path, len(data), host, port))
sock = socket.socket()
sock.settimeout(10)
sock.connect((host, port))
time.sleep(0.5)
try:
    sock.sendall(data)
except OSError as exc:
    print("send error:", exc)
time.sleep(2.0)

sock.settimeout(3.0)
out = b""
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
except OSError:
    pass
sock.close()

print("--- console output ---")
sys.stdout.write(out.decode("utf-8", "replace"))
print("\n--- done ---")
