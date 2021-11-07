#!/bin/python3
import os
import time

from vyper.cli import vyper_compile
import web3
from web3.middleware.geth_poa import geth_poa_middleware
from web3.providers.rpc import HTTPProvider
import dotenv
from eth_typing.evm import ChecksumAddress, HexAddress
import stat

ERC20_CONTRACT_PATH = "/erc20contract.vy"
AUDIT_PUBLISHER_CONTRACT_PATH = "/audit_contract.vy"
ETH_ENV_PATH = "/output/eth.env"
ETH_CONTRACTS_ENV_PATH = "/output/eth_contracts.env"
ETH_HOST = "http://geth:8545"
ETH_MAIN_ADDRESS_KEY = 'ETH_MAIN_ADDRESS'
ETH_CONTRACTS_OWNER_KEY = "ETH_CONTRACTS_OWNER"
GUSD_CONTRACT_ADDRESS_KEY = "GUSD_CONTRACT_ADDRESS"
AUDIT_PUBLISHER_CONTRACT_ADDRESS_KEY = "AUDIT_PUBLISHER_CONTRACT_ADDRESS"
BLOCK_NUMBER_KEY = "ETH_CONTRACTS_BLOCK_NUMBER"

dotenv.load_dotenv(ETH_ENV_PATH)
dotenv.load_dotenv(ETH_CONTRACTS_ENV_PATH)

def deploy_contract(contract_path, **constructor_kwargs):
    w3 = web3.Web3(provider=HTTPProvider(ETH_HOST), middlewares=(geth_poa_middleware,))
    compiled_contract = vyper_compile.compile_files(
        input_files=[contract_path],
        output_formats=["combined_json"],
    )
    contract_output = compiled_contract[contract_path.strip("/")]
    print(f"Finished compilation of {contract_path}", flush=True)
    Contract = w3.eth.contract(
        abi=contract_output["abi"], bytecode=contract_output["bytecode"]
    )
    tx_hash = Contract.constructor(**constructor_kwargs).transact({"from": os.environ[ETH_MAIN_ADDRESS_KEY]})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    contract_address = tx_receipt["contractAddress"]
    assert isinstance(contract_address, str)
    block_number = tx_receipt["blockNumber"]
    assert isinstance(block_number, int)
    return contract_address, block_number

def deploy_contract_retry(contract_path, **constructor_kwargs):
    num_attempts = 5
    for i in range(num_attempts):
        try:
            return deploy_contract(contract_path, **constructor_kwargs)
        except Exception as e:
            print("Exception with deploy: {e}", flush=True)
            time.sleep(1)
    raise e

def main():
    if ETH_CONTRACTS_OWNER_KEY in os.environ and os.environ[ETH_MAIN_ADDRESS_KEY] == os.environ[ETH_CONTRACTS_OWNER_KEY]:
        # nothing changed since last deploy
        print("Main same as last deploy", flush=True)
        return
    print("Deploying gusd contract", flush=True)
    gusd_contract_address, _ = deploy_contract_retry(ERC20_CONTRACT_PATH,  _name='GUSD'.encode("utf-8"), _symbol='GUSD'.encode("utf-8"), _totalSupply=2 ** 63, _decimals=2)
    print("Deploying audit contract", flush=True)
    audit_publisher_contract_address, block_number = deploy_contract_retry(AUDIT_PUBLISHER_CONTRACT_PATH)
    
    dotenv.set_key(ETH_CONTRACTS_ENV_PATH, GUSD_CONTRACT_ADDRESS_KEY, gusd_contract_address)
    dotenv.set_key(ETH_CONTRACTS_ENV_PATH, AUDIT_PUBLISHER_CONTRACT_ADDRESS_KEY, audit_publisher_contract_address)
    dotenv.set_key(ETH_CONTRACTS_ENV_PATH, ETH_CONTRACTS_OWNER_KEY, os.environ[ETH_MAIN_ADDRESS_KEY])
    dotenv.set_key(ETH_CONTRACTS_ENV_PATH, BLOCK_NUMBER_KEY, str(block_number))
    os.chmod(ETH_CONTRACTS_ENV_PATH, stat.S_IRGRP | stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)

if __name__ == "__main__":
    main()
