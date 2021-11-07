import logging
from concurrent.futures import ThreadPoolExecutor
from types import TracebackType
from typing import TYPE_CHECKING, Callable, Optional, Type

if TYPE_CHECKING:
    from concurrent.futures import Future  # pylint: disable=ungrouped-imports
    from typing import List  # pylint: disable=ungrouped-imports

LOGGER = logging.getLogger(__name__)


class ManagedThreadPool:
    def __init__(self, max_workers: int) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._futures: "List[Future[None]]" = []
        self._entered = False

    def __enter__(self) -> "ManagedThreadPool":
        assert not self._entered, "Thread pool already entered"
        self._entered = True
        return self

    def __call__(
        self,
        func: Callable[[], None],
    ) -> None:
        assert self._entered, "Thread pool not entered"
        self._futures.append(self._executor.submit(func))

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        exception: Optional[BaseException] = None
        while len(self._futures) > 0:
            future = self._futures.pop()
            try:
                future.result()
            except Exception as e:  # pylint: disable=broad-except
                LOGGER.warning("Exception in thread pool executor", exc_info=True)
                exception = e
        self._entered = False
        if exception is not None:
            raise exception
