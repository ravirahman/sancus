import uuid
from unittest.mock import Mock

import petlib.bn
import petlib.ec
from protobufs.institution.coldwallet_pb2 import CreateKeyPairsResponse

SECP256K1_CURVE_ID = 714

MOCK_SECP256K1_PRIVATE_KEY = petlib.bn.Bn.from_hex("18aab0ba55eccd8d13a8bf305722f971dca42b9625b7af7b53ed48ce8a6fcbfd")
MOCK_SECP256K1_PUBLIC_KEY = MOCK_SECP256K1_PRIVATE_KEY * petlib.ec.EcGroup(nid=SECP256K1_CURVE_ID).generator()
MOCK_SECP256K1_KEY_UUID = uuid.UUID("0ecd5dc8-5132-4c6b-8e8e-441ea5545b11")
MOCK_ETHEREUM_ADDRESS = "0x90f7260edD903B46c806A0Bce05752Ec50d755Fe"
MOCK_BITCOIN_ADDRESS = "1DpKH8SsDpmC37Yp4DwWXBbCPQQG7quG8T"

mock_public_key = CreateKeyPairsResponse.Key(
    keyId=MOCK_SECP256K1_KEY_UUID.bytes, publicKey=MOCK_SECP256K1_PRIVATE_KEY.binary()
)

mock_create_key_pairs_response = CreateKeyPairsResponse(publicKeys=[mock_public_key])

mock_create_key_pairs = Mock()
mock_create_key_pairs.return_value = mock_create_key_pairs_response

mock_generate_random_bn = Mock()
mock_generate_random_bn.return_value = MOCK_SECP256K1_PRIVATE_KEY
