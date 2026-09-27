"""Atomic unit of work shared by local tests and the Neo4j adapter."""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from threading import RLock
from typing import Protocol, TypeVar

from recallguard.models import AuditEvent, Grant, Memory, Source

T = TypeVar("T")


@dataclass
class State:
    sources: dict[str, Source] = field(default_factory=dict)
    memories: dict[str, Memory] = field(default_factory=dict)
    grants: dict[str, Grant] = field(default_factory=dict)
    events: dict[str, AuditEvent] = field(default_factory=dict)


class Store(Protocol):
    def transact(self, operation: Callable[[State], T]) -> T: ...
    def close(self) -> None: ...


class InMemoryStore:
    """Ephemeral test/development store. Never silently used on Neo4j failure."""

    def __init__(self):
        self._state = State()
        self._lock = RLock()

    def transact(self, operation: Callable[[State], T]) -> T:
        with self._lock:
            working = deepcopy(self._state)
            result = operation(working)
            self._state = working
            return deepcopy(result)

    def close(self) -> None:
        pass
