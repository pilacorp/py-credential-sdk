"""One deadline for a whole network call (connect, TLS handshake, headers, body)."""
from __future__ import annotations

import socket
import threading


class Deadline:
    """A recv timeout only bounds one recv, so at the deadline every tracked socket is shut down: a blocked
    read returns at once. Track the raw socket and, once wrapped, the TLS one (wrap_socket detaches the raw
    socket, so shutting it down would not close the connection). ``expired`` says the timer fired."""

    def __init__(self, seconds: float) -> None:
        self.expired = threading.Event()
        self._socks: list[socket.socket] = []
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True

    def start(self) -> None:
        self._timer.start()

    def cancel(self) -> None:
        self._timer.cancel()

    def track(self, sock: socket.socket) -> None:
        self._socks.append(sock)
        if self.expired.is_set():  # fired while the socket was being made
            self._shut(sock)

    def _fire(self) -> None:
        self.expired.set()
        for s in list(self._socks):
            self._shut(s)

    @staticmethod
    def _shut(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
