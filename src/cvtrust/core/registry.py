"""A minimal, typed plugin registry (ADR-001).

Dataset adapters, feature extractors and detectors are all looked up by name so
that the platform is not wired around one CV format or one architecture.  The
registry is deliberately tiny — no entry-point scanning, no import magic — so
that in an air-gapped deployment the set of loaded components is exactly what
the code imports, and is auditable by reading one file.
"""

from __future__ import annotations

from typing import Callable, Generic, Iterator, TypeVar

from .errors import ConfigError

T = TypeVar("T")


class Registry(Generic[T]):
    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._items: dict[str, T] = {}

    def register(self, name: str) -> Callable[[T], T]:
        def decorator(item: T) -> T:
            if name in self._items:
                raise ConfigError(f"duplicate {self._kind} registration: {name!r}")
            self._items[name] = item
            return item

        return decorator

    def add(self, name: str, item: T) -> None:
        self.register(name)(item)

    def get(self, name: str) -> T:
        try:
            return self._items[name]
        except KeyError:
            raise ConfigError(
                f"unknown {self._kind} {name!r}; available: {', '.join(self.names())}"
            ) from None

    def names(self) -> list[str]:
        return sorted(self._items)

    def __iter__(self) -> Iterator[tuple[str, T]]:
        return iter(sorted(self._items.items()))

    def __contains__(self, name: object) -> bool:
        return name in self._items

    def __len__(self) -> int:
        return len(self._items)
