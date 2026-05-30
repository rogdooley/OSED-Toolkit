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
    def __init__(self, host, port, timeout=3.0):
        # type: (str, int, float) -> None
        self._host = host
        self._port = port
        self._timeout = timeout

    def send(self, payload):
        # type: (bytes) -> None
        with socket.create_connection((self._host, self._port), self._timeout) as sock:
            sock.sendall(payload)


class UDPSender(Sender):
    def __init__(self, host, port, timeout=3.0):
        # type: (str, int, float) -> None
        self._host = host
        self._port = port
        self._timeout = timeout

    def send(self, payload):
        # type: (bytes) -> None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self._timeout)
            sock.sendto(payload, (self._host, self._port))
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
        )
    if transport_type == "udp":
        return UDPSender(
            host=transport_config["host"],
            port=transport_config["port"],
            timeout=float(transport_config.get("timeout", 3.0)),
        )
    if transport_type == "callback":
        return CallbackSender(callback_name=transport_config["callback_name"])
    raise ValueError("unsupported transport type: {}".format(transport_type))


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
