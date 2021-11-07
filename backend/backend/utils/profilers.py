import logging
import os
import threading
from csv import writer
from datetime import datetime
from typing import Any

from common.constants import Blockchain
from common.utils.datetime import get_current_datetime
from hexbytes.main import HexBytes

from backend.utils.blockchain_client.vendor_base import BlockMetadata

# from backend.utils.blockchain_client.client import BlockchainClient

LOGGER = logging.getLogger(__name__)


def write_latency_output_to_folder(output_dir: str, method_name: str, start_time: datetime, end_time: datetime) -> None:
    latency = end_time - start_time
    thread_id = threading.get_ident()

    os.makedirs(output_dir, exist_ok=True)

    if not os.path.isfile(f"{output_dir}/thread_{thread_id}.csv"):
        with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
            writer_object = writer(f)
            writer_object.writerow(["method_name", "start_time", "end_time", "latency"])

    with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
        writer_object = writer(f)
        writer_object.writerow([method_name, start_time, end_time, latency])


def record_latency(handler: Any) -> Any:  # type: ignore[misc]
    profile_data_folder = os.environ.get("PROFILE_DATA_FOLDER")
    if profile_data_folder is None:
        return handler

    def wrapper(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        profile_data_folder = os.environ.get("PROFILE_DATA_FOLDER")
        start_time = get_current_datetime()
        resp = handler(*args, **kwargs)
        end_time = get_current_datetime()

        profile_data_folder = os.path.join(profile_data_folder, "test_output")  # type: ignore[arg-type]
        output_dir = os.path.join(profile_data_folder, handler.__name__)

        write_latency_output_to_folder(output_dir, handler.__name__, start_time, end_time)
        return resp

    return wrapper


def write_latency_output_to_folder_process_block(
    output_dir: str, method_name: str, start_time: datetime, end_time: datetime, block_metadata: BlockMetadata
) -> None:
    latency = end_time - start_time
    thread_id = threading.get_ident()

    os.makedirs(output_dir, exist_ok=True)

    if not os.path.isfile(f"{output_dir}/thread_{thread_id}.csv"):
        with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
            writer_object = writer(f)
            writer_object.writerow(
                [
                    "method_name",
                    "start_time",
                    "end_time",
                    "latency",
                    "block_number",
                    "block_hash",
                    "parent_block_hash",
                    "block_timestamp",
                ]
            )

    with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
        writer_object = writer(f)
        writer_object.writerow(
            [
                method_name,
                start_time,
                end_time,
                latency,
                block_metadata.block_number,
                block_metadata.block_hash,
                block_metadata.parent_block_hash,
                block_metadata.block_timestamp,
            ]
        )


def record_latency_process_block(handler: Any) -> Any:  # type: ignore[misc]
    profile_data_folder = os.environ.get("PROFILE_DATA_FOLDER")
    if profile_data_folder is None:
        return handler

    def wrapper(self, blockchain: Blockchain, block_number: int) -> Any:  # type: ignore[misc, no-untyped-def]
        profile_data_folder = os.environ.get("PROFILE_DATA_FOLDER")
        start_time = get_current_datetime()
        resp = handler(self, blockchain, block_number)
        end_time = get_current_datetime()

        block_metadata = self.get_block_metadata_from_chain(blockchain, block_number)

        profile_data_folder = os.path.join(profile_data_folder, "test_output")  # type: ignore[arg-type]
        output_dir = os.path.join(profile_data_folder, handler.__name__)

        write_latency_output_to_folder_process_block(output_dir, handler.__name__, start_time, end_time, block_metadata)
        return resp

    return wrapper


def record_file_size(outfile_name: str) -> None:
    profile_data_folder = os.environ.get("PROFILE_DATA_FOLDER")
    if profile_data_folder is None:
        return

    file_size = os.stat(outfile_name).st_size
    output_dir = os.path.join(profile_data_folder, "size")
    thread_id = threading.get_ident()

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    if not os.path.isfile(f"{output_dir}/thread_{thread_id}.csv"):
        with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
            writer_object = writer(f)
            writer_object.writerow(["outfile_name", "size_bytes"])

    with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
        writer_object = writer(f)
        writer_object.writerow([outfile_name, file_size])


def record_txn_hash(blockchain: Blockchain, txn_hash: HexBytes) -> None:
    profile_data_folder = os.environ.get("PROFILE_DATA_FOLDER")
    if profile_data_folder is None:
        return

    assert isinstance(profile_data_folder, str)
    txn_hash_output_dir = os.path.join(profile_data_folder, "txn_hash_output")
    thread_id = threading.get_ident()

    if not os.path.isdir(txn_hash_output_dir):
        os.makedirs(txn_hash_output_dir)

    if not os.path.isfile(f"{txn_hash_output_dir}/thread_{thread_id}.csv"):
        with open(f"{txn_hash_output_dir}/thread_{thread_id}.csv", "a") as f:
            writer_object = writer(f)
            writer_object.writerow(["blockchain", "txn_hash"])

    with open(f"{txn_hash_output_dir}/thread_{thread_id}.csv", "a") as f:
        writer_object = writer(f)
        writer_object.writerow([blockchain, txn_hash.hex()])
