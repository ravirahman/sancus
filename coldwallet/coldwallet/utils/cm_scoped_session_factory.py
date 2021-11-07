from types import TracebackType
from typing import Optional, Type

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.util import ThreadLocalRegistry


class CMScopedSessionFactory:
    """Scoped Session Factory with the Python context manager API"""

    def __init__(self, session_maker: sessionmaker):
        self._session_registry = ThreadLocalRegistry(session_maker)
        self._counter_registry = ThreadLocalRegistry(lambda: 0)

    def __enter__(self) -> Session:
        session = self._session_registry()
        assert isinstance(session, Session)
        self._counter_registry.set(self._counter_registry() + 1)
        return session

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self._counter_registry.set(self._counter_registry() - 1)
        if self._counter_registry() == 0:
            self._session_registry().close()
            self._session_registry.clear()
            self._counter_registry.clear()
