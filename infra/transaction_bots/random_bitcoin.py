# currently only supports transfers from default accounts

import bitcoin
import bitcoin.rpc
import random
import time

class RandomBitcoin():

    def __init__(self, p=0.1, max_accounts=20) -> None:
        bitcoin.SelectParams("regtest")
        for i in range(10):
            try:
                self.proxy = bitcoin.rpc.Proxy("http://bitcoin:password@bitcoin-core:18444")
                self.proxy.getbestblockhash()
                break
            except:
                print("Unable to connect. Sleeping 2s and trying again", flush=True)
                if i < 9:
                    time.sleep(2)
                else:
                    raise
        self.p = p
        self.max_accounts = max_accounts

    def list_addresses(self) -> list:
        ret = self.proxy.call("listunspent")
        ret = [r['address'] for r in ret]
        return list(ret)

    def get_address(self) -> str:
        if len(self.list_addresses()) <= self.max_accounts and random.uniform(0, 1) < self.p:
            return str(self.proxy.getnewaddress())
        else:
            return str(random.choice(self.list_addresses()))

    def get_amount(self) -> int:
        """returns a random amount sampled from a specified distribution"""
        # TODO: only using uniform random distribution for now
        return int(random.uniform(500, 1000))
        # return int(np.random.exponential(100))

    def make_transaction(self) -> None:
        addr = self.get_address()
        amount = self.get_amount()
        self.proxy.sendtoaddress(addr, amount)
        print(f'Sent {amount} to {addr}', flush=True)

    def run(self) -> None:
        while True:
            self.make_transaction()
            time.sleep(2)

if __name__ == '__main__':
    r = RandomBitcoin(0.2)
    r.run()
