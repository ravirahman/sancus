import time
from datetime import datetime, timedelta

from common.constants import SPIN_SLEEP_SECONDS


class Spinner:
    def __init__(self, interval: timedelta) -> None:
        self._last_check = datetime.now()
        self._interval = interval

    def __call__(self) -> bool:
        now = datetime.now()
        if self._last_check + self._interval > now:
            time.sleep(SPIN_SLEEP_SECONDS)
            return False
        self._last_check = now
        return True
