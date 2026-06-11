"""Transport adapters for payload delivery (Python 3.7, stdlib only)."""

import importlib
import socket
from abc import ABCMeta, abstractmethod
from typing import Callable, Optional


class Sender(metaclass=ABCMeta):
    """Simple transport abstraction used by the orchestrator."""

    @abstractmethod
    def send(self, payload):
        # type: (bytes) -> None
        raise NotImplementedError


class TCPSender(Sender):
    """
    TCP delivery with optional protocol framing.

    Many real targets require a command envelope around the fuzz payload and
    expect a banner to be consumed first (e.g. Vulnserver TRUN, POP3). The
    orchestrator only owns the payload bytes; framing lives here so the
    built-in transport can drive these targets without a custom callback.

        wire = prefix + payload + suffix

    ``prefix`` / ``suffix`` are taken from config as text and encoded with
    latin-1 so every byte 0x00-0xFF round-trips one-to-one (use JSON escapes
    such as "\\r\\n" for control bytes).
    """

    def __init__(self, host, port, timeout=3.0, prefix=b"", suffix=b"",
                 read_banner=False, banner_size=4096):
        # type: (str, int, float, bytes, bytes, bool, int) -> None
        self._host = host
        self._port = port
        self._timeout = timeout
        self._prefix = prefix
        self._suffix = suffix
        self._read_banner = read_banner
        self._banner_size = banner_size

    def send(self, payload):
        # type: (bytes) -> None
        with socket.create_connection((self._host, self._port), self._timeout) as sock:
            if self._read_banner:
                sock.recv(self._banner_size)
            sock.sendall(self._prefix + payload + self._suffix)


class UDPSender(Sender):
    """UDP delivery with optional prefix/suffix framing (no banner read)."""

    def __init__(self, host, port, timeout=3.0, prefix=b"", suffix=b""):
        # type: (str, int, float, bytes, bytes) -> None
        self._host = host
        self._port = port
        self._timeout = timeout
        self._prefix = prefix
        self._suffix = suffix

    def send(self, payload):
        # type: (bytes) -> None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self._timeout)
            sock.sendto(self._prefix + payload + self._suffix, (self._host, self._port))
        finally:
            sock.close()


class CallbackSender(Sender):
    def __init__(self, callback=None, callback_name=None):
        # type: (Optional[Callable[[bytes], None]], Optional[str]) -> None
        if callback is None and not callback_name:
            raise ValueError("callback or callback_name is required")
        if callback is not None and callback_name:
            raise ValueError("provide either callback or callback_name, not both")

        if callback_name:
            callback = _load_callback(callback_name)
        if callback is None or not callable(callback):
            raise TypeError("callback must be callable")
        self._callback = callback

    def send(self, payload):
        # type: (bytes) -> None
        self._callback(payload)


def build_sender(transport_config):
    # type: (dict) -> Sender
    transport_type = transport_config["type"]
    if transport_type == "tcp":
        return TCPSender(
            host=transport_config["host"],
            port=transport_config["port"],
            timeout=float(transport_config.get("timeout", 3.0)),
            prefix=_encode_frame(transport_config.get("prefix", "")),
            suffix=_encode_frame(transport_config.get("suffix", "")),
            read_banner=bool(transport_config.get("read_banner", False)),
            banner_size=int(transport_config.get("banner_size", 4096)),
        )
    if transport_type == "udp":
        return UDPSender(
            host=transport_config["host"],
            port=transport_config["port"],
            timeout=float(transport_config.get("timeout", 3.0)),
            prefix=_encode_frame(transport_config.get("prefix", "")),
            suffix=_encode_frame(transport_config.get("suffix", "")),
        )
    if transport_type == "callback":
        return CallbackSender(callback_name=transport_config["callback_name"])
    raise ValueError("unsupported transport type: {}".format(transport_type))


def _encode_frame(value):
    # type: (object) -> bytes
    """
    Encode a config-supplied prefix/suffix to bytes.

    Strings are encoded latin-1 so every codepoint 0x00-0xFF maps to the same
    byte. Already-bytes values pass through unchanged.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin-1")
    raise TypeError("transport prefix/suffix must be str or bytes")


def _load_callback(callback_name):
    # type: (str) -> Callable[[bytes], None]
    if ":" in callback_name:
        module_name, attr_name = callback_name.split(":", 1)
    else:
        parts = callback_name.split(".")
        if len(parts) < 2:
            raise ValueError("callback_name must include module and attribute")
        module_name = ".".join(parts[:-1])
        attr_name = parts[-1]

    module = importlib.import_module(module_name)
    callback = getattr(module, attr_name)
    if not callable(callback):
        raise TypeError("callback_name does not resolve to a callable")
    return callback
