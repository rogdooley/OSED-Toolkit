import struct
from pathlib import Path
def verify_pe(path: Path) -> None:
    data=path.read_bytes()
    if data[:2]!=b"MZ": raise ValueError("not a PE file")
    offset=struct.unpack_from("<I",data,0x3C)[0]
    if data[offset:offset+4]!=b"PE\0\0" or struct.unpack_from("<H",data,offset+4)[0]!=0x14C: raise ValueError("not i386 PE")
    if struct.unpack_from("<H",data,offset+24)[0]!=0x10B: raise ValueError("not PE32")
