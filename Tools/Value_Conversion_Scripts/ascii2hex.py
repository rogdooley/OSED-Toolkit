#!/usr/bin/env python3
 
import textwrap
import binascii
import sys
 
function_name = sys.argv[1]
bytes_function_name = (function_name[::-1]).encode("utf8")
padding = b"\x00"*(4-len(bytes_function_name)%4)
# print(padding+bytes_function_name)
 
print(textwrap.wrap((binascii.hexlify(padding+bytes_function_name).decode()), 8))