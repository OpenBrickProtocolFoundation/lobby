from threading import Lock
from types import TracebackType
from typing import Optional
from typing import Self


class Synchronized[T]:
    class _Proxy:
        def __init__(self, value: T) -> None:
            self._value = value
            self._lock = Lock()

        def get(self) -> T:
            return self._value

        def __enter__(self) -> Self:
            self._lock.acquire()
            return self

        def __exit__(
                self,
                exc_type: Optional[type[BaseException]],
                exc_val: Optional[BaseException],
                exc_tb: Optional[TracebackType]
        ) -> bool:
            self._lock.release()
            return exc_type is None

    def __init__(self, value: T) -> None:
        self._value = value

    def lock(self) -> _Proxy:
        return self._Proxy(self._value)
