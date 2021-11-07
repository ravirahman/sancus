import socket
import time
from datetime import datetime, timedelta


def wait_for_it(host: str, port: int, timeout: timedelta = timedelta(seconds=5)) -> None:
    deadline = datetime.now() + timeout
    while datetime.now() < deadline:
        with socket.socket() as sock:
            sock.settimeout(timeout.total_seconds())
            try:
                sock.connect((host, port))
            except ConnectionRefusedError:
                time.sleep(1)
                continue
            else:
                return
    raise Exception(f"Unable to connect to {host}:{port}")
