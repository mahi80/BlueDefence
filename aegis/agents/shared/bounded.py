"""Bounded containers for state keyed by values an attacker chooses (source IP, username, hostname …).

The SOC runs for weeks. A dict keyed by source IP that never forgets is a memory leak any botnet can drive
to an out-of-memory crash, so per-key state lives in a ``BoundedDict``: a dict that keeps the most recently
used ``maxlen`` keys and evicts the least recently used one when a new key arrives.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class BoundedDict(OrderedDict, Generic[K, V]):
    """Size-capped dict: writing a key moves it to the newest end; inserting past ``maxlen`` evicts the key
    written longest ago. Reads do not reorder (so ``dict(d)``, ``json.dumps(d)`` and iteration stay safe).

    ``on_evict(key, value)`` (optional) runs for each evicted entry — e.g. to adjust a running total."""

    def __init__(self, maxlen: int, *, on_evict: Callable[[K, V], None] | None = None):
        super().__init__()
        self.maxlen = max(1, int(maxlen))
        self.evicted = 0
        self._on_evict = on_evict

    def __setitem__(self, key: K, value: V) -> None:
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self.maxlen:
            old_key, old_value = self.popitem(last=False)
            self.evicted += 1
            if self._on_evict is not None:
                self._on_evict(old_key, old_value)

    def setdefault(self, key: K, default: V | None = None) -> V:  # type: ignore[override]
        if key in self:
            return super().__getitem__(key)
        self[key] = default  # type: ignore[assignment]
        return default  # type: ignore[return-value]


__all__ = ["BoundedDict"]
