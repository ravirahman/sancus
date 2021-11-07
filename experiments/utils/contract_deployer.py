import logging
import os
from typing import Tuple, cast

import web3
from vyper.cli import vyper_compile
from web3.middleware.geth_poa import geth_poa_middleware

from utils.constants import get_w3_provider

ERC20_CONTRACT_PATH = os.path.join(os.path.dirname(__file__), "erc20contract.vy")
AUDIT_PUBLISHER_CONTRACT_PATH = os.path.join(os.path.dirname(__file__), "audit_contract.vy")

LOGGER = logging.getLogger(__name__)


class ContractDeployer:
    def __init__(self, eth_main_address: str) -> None:
        self.w3 = web3.Web3(provider=get_w3_provider(), middlewares=(geth_poa_middleware,))
        self.eth_main_address = eth_main_address

    def deploy_contract(self, contract_path: str, **constructor_kwargs: object) -> str:
        compiled_contract = vyper_compile.compile_files(
            input_files=[contract_path],
            output_formats=["combined_json"],
        )
        contract_output = list(compiled_contract.values())[0]
        LOGGER.info("Finished compilation of %s", contract_path)
        contract_factory = self.w3.eth.contract(abi=contract_output["abi"], bytecode=contract_output["bytecode"])
        tx_hash = contract_factory.constructor(**constructor_kwargs).transact({"from": self.eth_main_address})
        tx_receipt = cast(web3.types.TxReceipt, self.w3.eth.waitForTransactionReceipt(tx_hash))
        contract_address = tx_receipt["contractAddress"]
        assert isinstance(contract_address, str)
        return contract_address

    def deploy_contracts(self) -> Tuple[str, str]:
        LOGGER.info("Deploying gusd contract")
        gusd_contract_address = self.deploy_contract(
            ERC20_CONTRACT_PATH,
            _name=b"GUSD",
            _symbol=b"GUSD",
            _totalSupply=2 ** 63,
            _decimals=2,
        )
        LOGGER.info("Deploying audit contract")
        audit_publisher_contract_address = self.deploy_contract(AUDIT_PUBLISHER_CONTRACT_PATH)
        return gusd_contract_address, audit_publisher_contract_address
