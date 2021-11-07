import json
import logging
import os
import queue
import signal
import socket
import tempfile
import threading
from datetime import timedelta
from typing import TYPE_CHECKING, Optional

import requests
from cid import CIDv0
from common.config import W3Config
from common.utils.ipfs_client import IPFSClient
from common.utils.spinner import Spinner
from sqlalchemy.exc import OperationalError
from web3 import Web3
from web3._utils.filters import LogFilter

from auditor.audit_processor import AuditProcessor

if TYPE_CHECKING:
    from web3.types import EventData  # pylint: disable=ungrouped-imports

with open(os.path.join(os.path.dirname(__file__), "audit_publisher_abi.json"), "r") as f:
    AUDIT_PUBLISHER_ABI = f.read()

LOGGER = logging.getLogger(__name__)


class AuditListener:
    def __init__(
        self,
        ipfs_client: IPFSClient,
        w3_config: W3Config,
        audit_eth_address: str,
        audit_processor: AuditProcessor,
    ) -> None:
        self._ipfs_client = ipfs_client
        self._w3 = Web3(provider=w3_config.provider, middlewares=w3_config.middlewares)
        self._start_block = w3_config.start_block_number
        self._audit_publisher_contract = self._w3.eth.contract(address=audit_eth_address, abi=AUDIT_PUBLISHER_ABI)
        self._audit_processor = audit_processor
        self.stopped = False
        self._fetcher_thread = threading.Thread(target=self.fetcher_loop)
        self._processing_thread = threading.Thread(target=self.processing_loop)
        self._event_queue: "queue.Queue[EventData]" = queue.Queue()

    def start(self) -> None:
        self._fetcher_thread.start()
        self._processing_thread.start()

    def stop(self) -> None:
        self.stopped = True
        self._fetcher_thread.join()
        self._processing_thread.join()

    def fetcher_loop(self) -> None:
        spinner = Spinner(timedelta(seconds=1))
        got_all_events = False
        event_filter: Optional[LogFilter] = None
        while not self.stopped:
            if not spinner():
                continue
            LOGGER.info("Spinning for audits...")
            try:
                if event_filter is None:
                    event_filter = self._audit_publisher_contract.events.Audit.createFilter(fromBlock=self._start_block)
                events = event_filter.get_new_entries() if got_all_events else event_filter.get_all_entries()
            except (
                socket.timeout,
                requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError,
            ):
                LOGGER.warning("Network error when retrieving events, but continuing", exc_info=True)
                continue
            except ValueError as e:
                if "filter not found" in str(e):
                    # this would mean that the ethereum node crashed and lost its filter state.
                    # Let's create a new filter
                    LOGGER.warning("Filter not found. Recreating the filter", exc_info=True)
                    event_filter = None
                    got_all_events = False
                else:
                    raise e
            except:  # pylint: disable=bare-except
                LOGGER.error("Failed to download audit - fatal error", exc_info=True)
                os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
            else:
                got_all_events = True
                for event in events:
                    self._event_queue.put_nowait(event)

    def processing_loop(self) -> None:
        spinner = Spinner(timedelta(seconds=1))
        while not self.stopped:
            if not spinner():
                continue
            LOGGER.info("Waiting for audits to process...")
            try:
                event = self._event_queue.get_nowait()
            except queue.Empty:
                continue
            while not self.stopped:
                try:
                    ipfs_address_bytes = event["args"]["ipfs_address"]
                    ipfs_address_hex = ipfs_address_bytes.hex()
                    LOGGER.info("Downloading audit %s from blockchain", ipfs_address_hex)
                    ipfs_address = CIDv0(ipfs_address_bytes)
                    with tempfile.TemporaryDirectory() as tempdir:
                        audit_tarfile_path = os.path.join(tempdir, f"{ipfs_address_hex}.tgz")
                        self._ipfs_client.download_to_file(ipfs_address, audit_tarfile_path)
                        self._audit_processor.process_audit(audit_tarfile_path)
                except (
                    socket.timeout,
                    OperationalError,
                    queue.Empty,
                    json.JSONDecodeError,
                    requests.exceptions.HTTPError,
                    requests.exceptions.ConnectionError,
                ):
                    LOGGER.error("Failed to process audit, but retrying", exc_info=True)
                    continue
                except:  # pylint: disable=bare-except
                    LOGGER.error("Failed to process audit - fatal error", exc_info=True)
                    os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
                else:
                    break
