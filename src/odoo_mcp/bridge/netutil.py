"""Client-address handling and a bounded per-key rate limiter."""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from contextvars import ContextVar

from starlette.requests import Request

DEFAULT_TRUSTED_PROXIES = ("127.0.0.0/8", "::1/128")

#: Address of the client making the current HTTP request (set by the throttle
#: middleware so provider hooks that never see the request can use it).
request_ip_var: ContextVar[str | None] = ContextVar("bridge_request_ip", default=None)

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class TrustedProxies:
    """Peers allowed to tell us the real client address via a header."""

    def __init__(self, entries: Iterable[str] = DEFAULT_TRUSTED_PROXIES) -> None:
        self._networks: list[_IpNetwork] = [
            ipaddress.ip_network(item, strict=False) for item in entries
        ]

    def trusts(self, peer: str | None) -> bool:
        if not peer:
            return False
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        return any(address in network for network in self._networks)


def client_ip(request: Request, header: str | None, trusted: TrustedProxies) -> str:
    """The proxy header's last value, but only when the socket peer is trusted."""
    peer = request.client.host if request.client else None
    if header and trusted.trusts(peer):
        value = request.headers.get(header, "")
        if value:
            return value.split(",")[-1].strip() or (peer or "unknown")
    return peer or "unknown"


class BoundedWindowLimiter:
    """Sliding-window limiter with a hard ceiling on tracked keys.

    When the key table is full, expired keys go first, then the least recently
    used key that is *not* over budget. If every key is over budget the new key
    is refused: an attacker rotating keys can neither reset their own bucket
    nor push a well-behaved caller out, and memory stays bounded.
    """

    def __init__(
        self,
        max_calls: int,
        window_seconds: float = 60.0,
        max_keys: int = 4096,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_calls = max_calls
        self.window = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _make_room_locked(self, now: float) -> bool:
        cutoff = now - self.window
        for key in [k for k, ev in self._events.items() if not ev or ev[-1] <= cutoff]:
            del self._events[key]
        if len(self._events) < self.max_keys:
            return True
        for key, events in self._events.items():  # least recently used first
            live = sum(1 for t in events if t > cutoff)
            if live < self.max_calls:
                del self._events[key]
                return True
        return False

    def hit(self, key: str) -> bool:
        """Record one call; ``False`` means over budget (the call is not counted)."""
        now = self._clock()
        cutoff = now - self.window
        with self._lock:
            events = self._events.get(key)
            if events is None:
                if len(self._events) >= self.max_keys and not self._make_room_locked(now):
                    return False
                events = self._events[key] = deque()
            while events and events[0] <= cutoff:
                events.popleft()
            self._events.move_to_end(key)
            if len(events) >= self.max_calls:
                return False
            events.append(now)
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
