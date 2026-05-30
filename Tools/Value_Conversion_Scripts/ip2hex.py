#!/usr/bin/env python3

import socket
import struct
import sys

def ip_to_hex(ip_address):
    # Convert the IP address to a packed binary format (network byte order)
    packed_ip = socket.inet_aton(ip_address)
    # Unpack the binary format into a number and convert it to little-endian hex
    hex_value = struct.unpack("<I", packed_ip)[0]
    # Return the hex representation of the number
    return hex(hex_value)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script_name.py <IP_ADDRESS>")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    
    try:
        # Convert IP to hex and print the result
        hex_value = ip_to_hex(ip_address)
        print(f"IP address {ip_address} in hex (little-endian): {hex_value}")
    except socket.error:
        print(f"Invalid IP address: {ip_address}")
        sys.exit(1)