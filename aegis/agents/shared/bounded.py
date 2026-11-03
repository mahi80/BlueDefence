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
_NONE = object()
V = TypeVar("V")


class BoundedDict(OrderedDict, Generic[K, V]):
    """Size-capped dict: writing a key moves it to the newest end; inserting past ``maxlen`` evicts the key
    written longest ago. Reads do not reorder (so ``dict(d)``, ``json.dumps(d)`` and iteration stay safe).

    ``on_evict(key, value)`` (optional) runs for each evicted entry — e.g. to adjust a running total."""

    def __init__(self, maxlen: int, *, on_evict: Callable[[K, V], None] | None = None,
                 keep_established: bool = False, pinned: Callable[[K], bool] | None = None):
        """``keep_established``: when full, evict the newest *arrival* instead of the least recently written
        key. For per-device liveness state an LRU is wrong: a real device that goes silent stops being written
        and becomes the first evicted — so a flood of spoofed names erases the very device whose silence is
        the alert. Established keys stay; the churn happens among the newcomers.
        ``pinned(key)``: never evicted (e.g. devices in the operator's inventory)."""
        super().__init__()
        self.maxlen = max(1, int(maxlen))
        self.evicted = 0
        self._on_evict = on_evict
        self._keep_established = keep_established
        self._pinned = pinned

    def __setitem__(self, key: K, value: V) -> None:
        if key in self:
            if not self._keep_established:
                self.move_to_end(key)
            super().__setitem__(key, value)
            return
        super().__setitem__(key, value)
        if len(self) > self.maxlen:
            self._evict(exclude=key)

    def _victim(self, exclude: K) -> object:
        # walk lazily from the evicting end: the old version copied every key into a list on each insert past the
        # cap, O(n) per alert (1.4 ms at 20k keys; review round 3 G7-9). Only pinned keys are ever skipped.
        for k in (reversed(self) if self._keep_established else iter(self)):
            if k == exclude or (self._pinned is not None and self._pinned(k)):
                continue
            return k
        return _NONE

    def _evict(self, *, exclude: K) -> None:
        while len(self) > self.maxlen:
            k = self._victim(exclude)
            if k is _NONE:
                break
            v = super().pop(k)
            self.evicted += 1
            if self._on_evict is not None:
                self._on_evict(k, v)
        # only the new key or pinned keys left to evict: the new key goes (pinned keys are bounded by config)
        if len(self) > self.maxlen and exclude in self and not (self._pinned is not None and self._pinned(exclude)):
            v = super().pop(exclude)
            self.evicted += 1
            if self._on_evict is not None:
                self._on_evict(exclude, v)

    def setdefault(self, key: K, default: V | None = None) -> V:  # type: ignore[override]
        if key in self:
            return super().__getitem__(key)
        self[key] = default  # type: ignore[assignment]
        return default  # type: ignore[return-value]


__all__ = ["BoundedDict"]
