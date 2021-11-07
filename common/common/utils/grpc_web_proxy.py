import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
from datetime import timedelta
from types import TracebackType
from typing import Optional, Type

from common.config import GRPCWebProxyConfig
from common.utils.spinner import Spinner

GRPC_WEB_PROXY_BINARY = shutil.which("grpcwebproxy")

LOGGER = logging.getLogger(__name__)


class GRPCWebProxy:
    def __init__(self, config: GRPCWebProxyConfig) -> None:
        self._config = config
        self._proc: Optional["subprocess.Popen[str]"] = None
        self._thread = threading.Thread(target=self.monitor)
        self._stopped = False
        assert GRPC_WEB_PROXY_BINARY is not None, "grpcwebproxy not found in path"

    def start(self) -> None:
        assert self._proc is None, "already started"
        assert not self._stopped, "already stopped"
        assert GRPC_WEB_PROXY_BINARY is not None, "grpcwebproxy not found in path"
        assert self._config.grpc_config.certificate_chain is not None
        assert not self._config.grpc_config.host.startswith("unix://"), "cannot use a UDS with the grpcwebproxy"
        args = [
            GRPC_WEB_PROXY_BINARY,
            f"--backend_addr={self._config.grpc_config.host}",
            f"--server_tls_cert_file={self._config.server_tls_cert_file}",
            f"--server_tls_key_file={self._config.server_tls_key_file}",
            f"--server_http_tls_port={self._config.server_http_tls_port}",
            f"--server_bind_address={self._config.server_bind_address}",
            "--backend_tls=true",
            f"--backend_tls_ca_files={self._config.grpc_config.certificate_chain}",
            "--run_tls_server=true",
            "--run_http_server=false",
        ]
        if self._config.use_websockets:
            args.append("--use_websockets=true")
        else:
            args.append("--use_websockets=false")
        if self._config.allow_all_origins:
            args.append("--allow_all_origins=true")
        else:
            assert self._config.allowed_origins is not None
            origins = ",".join(self._config.allowed_origins)
            args.append("--allow_all_origins=false")
            args.append(f"--allowed_origins={origins}")

        if self._config.allowed_headers is not None:
            headers = ",".join(self._config.allowed_headers)
            args.append(f"--allowed_headers={headers}")
        LOGGER.info("Starting grpcwebproxy with command: %s", " ".join(args))
        self._proc = subprocess.Popen(
            args,
            universal_newlines=True,
            stdin=subprocess.PIPE,
            stderr=sys.stderr,
            stdout=sys.stdout,
            shell=False,
        )
        self._thread.start()

    def __enter__(self) -> "GRPCWebProxy":
        self.start()
        return self

    def stop(self) -> None:
        assert self._proc is not None, "never started"
        assert self._thread is not None, "never started"
        self._stopped = True
        self._thread.join()

    def monitor(self) -> None:
        assert self._proc is not None, "never started"
        spinner = Spinner(timedelta(seconds=1))
        while not self._stopped:
            if not spinner():
                continue
            returncode = self._proc.poll()
            if returncode is not None:
                LOGGER.error("grpcwebproxy exited with returncode(%d)", returncode)
                # need to terminate the current process if error, since this is in the background loop
                os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
        self._proc.kill()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.stop()
