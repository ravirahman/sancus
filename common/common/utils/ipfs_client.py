import os
from types import TracebackType
from typing import Optional, Type

import cid
import ipfshttpclient

from common.config import IPFSConfig


class AlreadyConnectedError(Exception):
    pass


class IPFSClient:
    def __init__(self, ipfs_config: IPFSConfig) -> None:
        self._chunk_size = ipfs_config.chunk_size
        self._client = ipfshttpclient.connect(ipfs_config.ipfs_host_uri, session=True)

    def __enter__(self) -> "IPFSClient":
        return self

    def upload(self, filename: str) -> cid.CIDv0:
        result = self._client.add(filename, recursive=True)
        try:
            result_hash = result["Hash"]
        except (KeyError, TypeError):
            assert isinstance(result, list)
            for info in result:
                if info["Name"] == os.path.basename(filename):
                    result_hash = cid.make_cid(info["Hash"])
        return cid.make_cid(result_hash)

    def download_to_file(self, content_path: str, destination_name: str) -> None:
        with open(destination_name, "wb+") as f:  # using a tcp pool for this download
            offset = 0
            while True:
                content = self._client.cat(content_path, offset, self._chunk_size)
                if len(content) == 0:
                    break
                f.write(content)
                offset += self._chunk_size

    def download(self, content_id: cid.CIDv0) -> bytes:
        ans: bytes = self._client.cat(content_id)
        return ans

    def close(self) -> None:
        self._client.close()

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        self.close()
