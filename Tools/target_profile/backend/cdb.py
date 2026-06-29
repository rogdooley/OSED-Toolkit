from dataclasses import dataclass

def _write_script(self, text: str) -> Path:
    ...

@dataclass
class CdbBackend:
    cdb_path: Path
    target_command: list[str]
    dump_path: Path
    timeout: float = 10.0

    def capture_dump(...):

        # remove stale dump

        # render WDS

        # write temporary WDS file

        # launch cdb

        # sender.send(payload)

        # wait for dump

        # terminate cdb if necessary

        # return dump bytes