import os
import tempfile
import unittest
from unittest.mock import patch

from protobufs.institution.coldwallet_pb2 import (
    CreateKeyPairsRequest,
    CreateKeyPairsResponse,
)

from coldwallet.coldwallet import ColdWallet
from tests.fixtures import mock_create_key_pairs, mock_create_key_pairs_response


class TestColdWallet(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        db_uri = f"sqlite:///{self.tempdir.name}/test.db"
        self.coldwallet = ColdWallet(db_uri)

    def test_handler(self) -> None:
        request = CreateKeyPairsRequest(numKeys=2)
        with tempfile.TemporaryDirectory() as tempdir:
            infile = os.path.join(tempdir, "request.protobuf")
            outfile = os.path.join(tempdir, "response.protobuf")
            with open(infile, "wb") as f:
                f.write(request.SerializeToString())
            with patch.object(
                self.coldwallet._servicer, "CreateKeyPairs", mock_create_key_pairs  # pylint: disable=protected-access
            ):
                self.coldwallet.handler("CreateKeyPairs", infile, outfile)
            response = CreateKeyPairsResponse()
            with open(outfile, "rb") as f:
                response.ParseFromString(f.read())

        self.assertEqual(response, mock_create_key_pairs_response)

    def test_cli(self) -> None:
        pass

    def tearDown(self) -> None:
        self.tempdir.cleanup()


if __name__ == "__main__":
    unittest.main()
