import csv
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Callable, List, TypeVar

import bitcoin
import bitcoin.rpc
import numpy as np
from common.config import BTCProxyConfig
from web3 import Web3

LOGGER = logging.getLogger(__name__)
TResponse = TypeVar("TResponse")


class ExperimentProcessor:
    def __init__(
        self,
        outfile: str,
        btc_outfile: str,
        eth_outfile: str,
        current_time: str,
        experiment_name: str,
        w3: Web3,
    ) -> None:
        self.outfile = outfile
        self.btc_outfile = btc_outfile
        self.eth_outfile = eth_outfile
        self.current_time = current_time
        self.experiment_name = experiment_name
        self.w3 = w3
        self._config = BTCProxyConfig(
            btc_service_url="http://bitcoin:password@localhost:18444",
            btc_node_type="regtest",
            start_block_number=1,
            max_workers=10,
        )

    @staticmethod
    def try_repeat_timeout(func: Callable[[], TResponse], timeout: timedelta) -> TResponse:
        deadline = datetime.now() + timeout
        while True:
            try:
                return func()
            except Exception as e:
                if datetime.now() < deadline:
                    # LOGGER.info("Check failed; sleeping 1 second and trying again")
                    time.sleep(1)
                    continue
                LOGGER.error("Try-repeat-timeout failed", exc_info=True)
                raise Exception("Try-repeat-timeout failed") from e

    def write_metadata_to_csv(self, name: str, desc: str, units: str, data: List) -> None:  # type: ignore[type-arg]
        percentiles = [0, 10, 25, 50, 75, 90, 99, 100]

        with open(self.outfile, "a", newline="") as output:
            csv_writer = csv.writer(output)
            csv_writer.writerow(
                [name, desc, units, len(data), np.mean(data)] + [np.percentile(data, q) for q in percentiles]
            )

    def process_db_sizes(self) -> None:
        db_names = ["auditor", "backend"]

        for db_name in db_names:
            db_output_csv = os.path.join(
                os.getcwd(),
                "results",
                self.experiment_name,
                self.current_time,
                f"profile/{db_name}_db/{db_name}_db_size.csv",
            )
            with open(db_output_csv) as db_output_csv_file:
                db_csv_reader = csv.reader(db_output_csv_file)
                for row in db_csv_reader:
                    if row[0] != "audit_version":
                        self.write_metadata_to_csv(f"{db_name}.{row[2]}", "db table", "bytes", [int(row[3])])

    def process_grpc_latency_output(self) -> None:

        grpc_latency_output_dir = os.path.join(
            os.getcwd(), "results", self.experiment_name, self.current_time, "profile/grpc_latency_output"
        )
        grpc_metadata = {}

        for thread in os.listdir(grpc_latency_output_dir):
            with open(os.path.join(grpc_latency_output_dir, thread)) as grpc_thread:
                csv_reader = csv.reader(grpc_thread)
                for row in csv_reader:
                    if row[0] != "method_name":
                        latency = (datetime.strptime(row[3], "%H:%M:%S.%f") - datetime(1900, 1, 1)).total_seconds()
                        if row[0] not in grpc_metadata:
                            grpc_metadata[row[0]] = [latency]
                        else:
                            grpc_metadata[row[0]].append(latency)

        for grpc in grpc_metadata:
            self.write_metadata_to_csv(grpc, "grpc method latency", "s", grpc_metadata[grpc])

    def process_process_audit_latency(self) -> None:

        profile_dir = os.listdir(
            os.path.join(os.getcwd(), "results", self.experiment_name, self.current_time, "profile")
        )
        audit_dirs = [d for d in profile_dir if "process_audit" in d]

        for audit_dir in audit_dirs:
            process_audit_latency_output_dir = os.path.join(
                os.getcwd(), "results", self.experiment_name, self.current_time, f"profile/{audit_dir}"
            )
            for thread in os.listdir(process_audit_latency_output_dir):
                with open(os.path.join(process_audit_latency_output_dir, thread)) as process_audit_thread:
                    csv_reader = csv.reader(process_audit_thread)
                    for row in csv_reader:
                        if row[0] != "audit_version":
                            latency = (datetime.strptime(row[3], "%H:%M:%S.%f") - datetime(1900, 1, 1)).total_seconds()
                            self.write_metadata_to_csv(audit_dir, "audit processing latency", "s", [latency])

    def process_process_block_latency_output(self) -> None:

        process_block_latency_output_dir = os.path.join(
            os.getcwd(), "results", self.experiment_name, self.current_time, "profile/test_output/process_block"
        )
        process_block_latency_data = []

        for thread in os.listdir(process_block_latency_output_dir):
            with open(os.path.join(process_block_latency_output_dir, thread)) as process_block_thread:
                csv_reader = csv.reader(process_block_thread)
                for row in csv_reader:
                    if row[0] != "method_name":
                        latency = (datetime.strptime(row[3], "%H:%M:%S.%f") - datetime(1900, 1, 1)).total_seconds()
                        process_block_latency_data.append(latency)

        self.write_metadata_to_csv(
            "blockchain processing loop", "blockchain processing loop latency", "s", process_block_latency_data
        )

    def process_pb_size(self) -> None:

        pb_size_output_dir = os.path.join(
            os.getcwd(), "results", self.experiment_name, self.current_time, "profile/size"
        )
        pb_metadata = {}

        for thread in os.listdir(pb_size_output_dir):
            with open(os.path.join(pb_size_output_dir, thread)) as pb_thread:
                csv_reader = csv.reader(pb_thread)
                for row in csv_reader:
                    if row[0] != "outfile_name":
                        pb_fname, pb_size = row
                        pb_name = pb_fname.split("/")[-2]
                        if pb_name not in pb_metadata:
                            pb_metadata[pb_name] = [int(pb_size)]
                        else:
                            pb_metadata[pb_name].append(int(pb_size))

        for pb_name in pb_metadata:
            self.write_metadata_to_csv(pb_name, "protobuf size", "bytes", pb_metadata[pb_name])

    def process_audit_gen_latency(self) -> None:

        audit_gen_latency_dir = os.path.join(
            os.getcwd(), "results", self.experiment_name, self.current_time, "profile/test_output"
        )
        method_metadata = {}

        for method in os.listdir(audit_gen_latency_dir):
            if method != "process_block":
                for thread in os.listdir(os.path.join(audit_gen_latency_dir, method)):
                    with open(os.path.join(audit_gen_latency_dir, method, thread)) as audit_gen_thread:
                        csv_reader = csv.reader(audit_gen_thread)
                        for row in csv_reader:
                            if row[0] != "method_name":
                                latency = (
                                    datetime.strptime(row[3], "%H:%M:%S.%f") - datetime(1900, 1, 1)
                                ).total_seconds()
                                if row[0] not in method_metadata:
                                    method_metadata[row[0]] = [latency]
                                else:
                                    method_metadata[row[0]].append(latency)

        for method in method_metadata:
            self.write_metadata_to_csv(method, "audit gen method latency", "s", method_metadata[method])

    def process_blockchain_transactions(self) -> None:

        LOGGER.info("Checking connection to w3: %s", self.w3.isConnected())

        blockchain_transaction_output_dir = os.path.join(
            os.getcwd(), "results", self.experiment_name, self.current_time, "profile/txn_hash_output"
        )
        proxy = bitcoin.rpc.Proxy(self._config.btc_service_url)
        for thread in os.listdir(blockchain_transaction_output_dir):
            with open(os.path.join(blockchain_transaction_output_dir, thread)) as tx_thread:
                csv_reader = csv.reader(tx_thread)
                for row in csv_reader:
                    if row[0] == "Blockchain.BTC":
                        txn_bytes = bytes.fromhex(row[1][2:])

                        def get_raw_transaction(txn: bytes = txn_bytes):  # type: ignore[no-untyped-def]
                            def underlying():  # type: ignore[no-untyped-def]
                                return proxy.getrawtransaction(txid=txn, verbose=True)

                            txn = self.try_repeat_timeout(underlying, timedelta(seconds=5))
                            return txn

                        txn = get_raw_transaction()
                        with open(self.btc_outfile, "a", newline="") as f:
                            f_csv = csv.writer(f)
                            f_csv.writerow(
                                [
                                    txn["hash"],
                                    txn["size"],
                                    txn["vsize"],
                                    txn["weight"],
                                    txn["blockhash"],
                                    txn["confirmations"],
                                    txn["time"],
                                    txn["blocktime"],
                                ]
                            )

                    elif row[0] == "Blockchain.ETH":
                        eth_receipt = self.w3.eth.getTransactionReceipt(bytes.fromhex(row[1][2:]))
                        with open(self.eth_outfile, "a", newline="") as f:
                            f_csv = csv.writer(f)
                            f_csv.writerow(
                                [
                                    eth_receipt["blockHash"],  # type: ignore[index]
                                    eth_receipt["blockNumber"],  # type: ignore[index]
                                    eth_receipt["cumulativeGasUsed"],  # type: ignore[index]
                                    eth_receipt["from"],  # type: ignore[index]
                                    eth_receipt["gasUsed"],  # type: ignore[index]
                                    eth_receipt["to"],  # type: ignore[index]
                                    eth_receipt["transactionHash"],  # type: ignore[index]
                                    eth_receipt["transactionIndex"],  # type: ignore[index]
                                ]
                            )

    def execute_script(self) -> None:
        if not os.path.isfile(self.outfile):
            with open(self.outfile, "a", newline="") as f:
                f_csv = csv.writer(f)
                f_csv.writerow(
                    [
                        "name",
                        "type",
                        "units",
                        "count",
                        "average",
                        "min",
                        "10%tile",
                        "25%tile",
                        "50%tile",
                        "75%tile",
                        "90%tile",
                        "99%tile",
                        "max",
                    ]
                )
        if not os.path.isfile(self.btc_outfile):
            with open(self.btc_outfile, "a", newline="") as f:
                f_csv = csv.writer(f)
                f_csv.writerow(
                    [
                        "hash",
                        "size",
                        "vsize",
                        "weight",
                        "blockhash",
                        "confirmations",
                        "time",
                        "blocktime",
                    ]
                )
        if not os.path.isfile(self.eth_outfile):
            with open(self.eth_outfile, "a", newline="") as f:
                f_csv = csv.writer(f)
                f_csv.writerow(
                    [
                        "blockHash",
                        "blockNumber",
                        "cumulativeGasUsed",
                        "from",
                        "gasUsed",
                        "to",
                        "transactionHash",
                        "transactionIndex",
                    ]
                )

        self.process_db_sizes()
        self.process_grpc_latency_output()
        self.process_process_block_latency_output()
        self.process_process_audit_latency()
        self.process_pb_size()
        self.process_audit_gen_latency()

        if os.path.isdir(
            os.path.join(os.getcwd(), "results", self.experiment_name, self.current_time, "profile/txn_hash_output")
        ):
            self.process_blockchain_transactions()
