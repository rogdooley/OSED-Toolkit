class FakeBackend:
    def capture_dump(self, breakpoint_expr, dump_expr, sender):

        if dump_expr == "poi(@esp+4)+9":
            return MAGIC + bytes(range(1, 20))

        return b"\x00" * 32
