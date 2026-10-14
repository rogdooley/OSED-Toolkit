def build_bytearray(start=0,end=255,excluded=set(),repeat=1):
    return bytes(x for _ in range(repeat) for x in range(start,end+1) if x not in excluded)
def single_probe(value): return bytes([value])
def pair_probe(left,right): return bytes([left,right])
