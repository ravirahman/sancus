import requests
from web3.providers.rpc import HTTPProvider

BTC_HOST = "http://bitcoin:password@localhost:18444"
ETH_HOST = "http://localhost:8545"
IPFS_HOST = "/ip4/127.0.0.1/tcp/5001"
WEBAUTHN_ORIGIN = "http://localhost:3000"

MAX_ETH_WORKERS = 25
MAX_BTC_WORKERS = 10


def get_w3_provider() -> HTTPProvider:
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=MAX_ETH_WORKERS,
        pool_maxsize=MAX_ETH_WORKERS,
        max_retries=5,
        pool_block=True,
    )
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return HTTPProvider(ETH_HOST, session=session, request_kwargs={"timeout": 60})
