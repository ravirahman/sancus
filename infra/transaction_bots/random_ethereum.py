from web3.providers.rpc import HTTPProvider
from web3.middleware.geth_poa import geth_poa_middleware
import web3
import random
import time
import urllib3
import requests

passwords = ["passphrase", "password"]

class RandomEthereum():

    def __init__(self, p=0.1, max_accounts=100) -> None:
        print("Starting ETH transaction bot", flush=True)
        provider = HTTPProvider("http://geth:8545")
        provider.middlewares = []
        self.w3 = web3.Web3(provider, middlewares=[geth_poa_middleware])
        for i in range(10):
            try:
                self.w3.eth.get_block("latest")
                break
            except requests.exceptions.ConnectionError:
                print("Unable to connect. Sleeping 1s and trying again", flush=True)
                if i < 9:
                    time.sleep(1)
                else:
                    raise

        # self.w3 = web3.Web3(HTTPProvider("http://localhost:8545"))
        self.default_addr = '0x27FC0Eba4ca67e27CE0b6B4e4C6f8b6afb5c4029'
        self.unlocked_accounts = []
        self.unlock_all_accounts()
        self.p = p
        self.max_accounts = max_accounts

    def unlock_all_accounts(self) -> None:
        print("Unlocking accounts", flush=True)
        addrs = self.w3.eth.get_accounts()
        for addr in addrs:
            for pw in passwords:
                try:
                    print(f"Unlocking account {addr}", flush=True)
                    self.w3.geth.personal.unlock_account(addr, pw)
                except ValueError as e:
                    if 'could not decrypt key with given password' in str(e):
                        continue
                self.unlocked_accounts.append(addr)
                break

    def get_balance(self, addr:str) -> int:
        return self.w3.eth.get_balance(addr)

    def get_from_address_and_amount(self) -> tuple:
        addrs = self.unlocked_accounts
        # it = 0
        # while it < 3:
        while True:
            addr = random.choice(addrs)
            # if addr == self.default_addr:
            #     continue
            bal = self.get_balance(addr)
            if bal > 0 and addr in self.unlocked_accounts:
                return (addr, max(min(bal, self.get_amount(bal)), 1))
        # return (self.default_addr, 100) # default address

    def get_to_address(self) -> str:
        if len(self.unlocked_accounts) <= self.max_accounts and random.uniform(0, 1) < self.p:
            new_addr = self.w3.geth.personal.new_account("passphrase")
            self.w3.geth.personal.unlock_account(new_addr, "passphrase")
            self.unlocked_accounts.append(new_addr)
            print(f"Created new account {new_addr}", flush=True)
            return str(new_addr)
        else:
            return str(random.choice(self.unlocked_accounts))

    def get_amount(self, b: int) -> int:
        """returns a random amount sampled from a specified distribution"""
        if b > 10000:
            b = 10000
        # TODO: only using uniform random distribution for now
        return int(random.uniform(0, 1) * b)
        # return int(np.random.exponential(b * random.uniform(0, 1)))

    def make_transaction(self) -> None:
        from_addr, amount = self.get_from_address_and_amount()
        to_addr = self.get_to_address()
        self.w3.eth.sendTransaction({
            "from": from_addr, 
            "to": to_addr, 
            "value": amount
        })
        print(f'Sent {amount} from {from_addr} to {to_addr}', flush=True)
        # print(f'Balance of {from_addr} is now {self.get_balance(from_addr)}', flush=True)
        # print(f'Balance of {to_addr} is now{self.get_balance(to_addr)}', flush=True)

    def print_all_addr_info(self) -> None:
        addrs = self.unlocked_accounts
        print(f'addr \t balance', flush=True)
        for addr in addrs:
            bal = self.get_balance(addr)
            print(f'{addr} \t {bal}', flush=True)

    def run(self) -> None:
        while True:
            # self.print_all_addr_info()
            self.make_transaction()
            time.sleep(2)


if __name__ == '__main__':
    r = RandomEthereum(0.2)
    r.run()
