import tempfile
import unittest
import uuid
from unittest.mock import patch

import petlib.bn
import petlib.ec
import zksk
from bitcoin.core import CMutableTransaction
from bitcoin.core.scripteval import SCRIPT_VERIFY_P2SH, VerifyScript
from bitcoin.wallet import CBitcoinAddress
from eth_account import Account
from protobufs.bitcoin_pb2 import (
    BitcoinTransactionDestination,
    BitcoinTransactionSource,
    BitcoinTxParams,
)
from protobufs.eth_pb2 import EthereumTxParams
from protobufs.institution.coldwallet_pb2 import (
    CreateKeyPairsRequest,
    SignBitcoinTransactionsRequest,
    SignEthereumTransactionsRequest,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from coldwallet.servicer import ColdWalletServicer
from coldwallet.sql.base import Base
from coldwallet.sql.models.key import Key
from coldwallet.utils.cm_scoped_session_factory import CMScopedSessionFactory
from tests.fixtures import (
    MOCK_BITCOIN_ADDRESS,
    MOCK_ETHEREUM_ADDRESS,
    MOCK_SECP256K1_KEY_UUID,
    MOCK_SECP256K1_PRIVATE_KEY,
    MOCK_SECP256K1_PUBLIC_KEY,
    mock_generate_random_bn,
)

SECP256K1_CURVE_ID = 714
SECP256K1_GROUP = petlib.ec.EcGroup(nid=SECP256K1_CURVE_ID)
SECP256K1_GENERATOR = SECP256K1_GROUP.generator()


class TestServicerBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        db_uri = f"sqlite:///{self.tempdir.name}/test.db"
        engine = create_engine(db_uri, echo=False)
        Base.metadata.create_all(engine)
        self._session_factory = CMScopedSessionFactory(sessionmaker(bind=engine))
        self.servicer = ColdWalletServicer(self._session_factory)

    def tearDown(self) -> None:
        self.tempdir.cleanup()


class TestCreateKeyPairs(TestServicerBase):
    @patch("coldwallet.utils.random_bn._generate_random_bn", mock_generate_random_bn)
    def test_create_key_pairs(self) -> None:  # type: ignore[misc]
        request = CreateKeyPairsRequest(numKeys=1)
        response = self.servicer.CreateKeyPairs(request)

        self.assertEqual(len(response.publicKeys), 1)
        created_public_key_protobuf = response.publicKeys[0]
        created_public_key = petlib.ec.EcPt.from_binary(created_public_key_protobuf.publicKey, SECP256K1_GROUP)
        created_key_uuid = uuid.UUID(bytes=created_public_key_protobuf.keyId)
        self.assertEqual(created_public_key, MOCK_SECP256K1_PUBLIC_KEY)
        x_prime = petlib.bn.Bn.from_binary(created_public_key_protobuf.permutedPrivateKey)
        Y_prime = x_prime * SECP256K1_GENERATOR  # pylint: disable=invalid-name
        k_s = zksk.Secret(name="k_s")
        stmt = zksk.DLRep(Y_prime, k_s * created_public_key)
        nizk = zksk.base.NIZK.deserialize(created_public_key_protobuf.permutationNIZK)
        self.assertTrue(stmt.verify(nizk))

        with self._session_factory as session:
            key = session.query(Key).filter(Key.key_uuid == created_key_uuid).one()
        private_key = key.private_key
        self.assertEqual(MOCK_SECP256K1_PRIVATE_KEY, private_key, "public key mistmatch")
        self.assertEqual(MOCK_ETHEREUM_ADDRESS, key.ethereum_address, "ethereum address mismatch")
        self.assertEqual(MOCK_BITCOIN_ADDRESS, key.bitcoin_address, "bitcoin address mismatch")


class TestSignEthereumTransactions(TestServicerBase):
    def setUp(self) -> None:
        super().setUp()
        with self._session_factory as session:
            key = Key(
                key_uuid=MOCK_SECP256K1_KEY_UUID,
                private_key=MOCK_SECP256K1_PRIVATE_KEY,
            )
            session.add(key)
            session.commit()

    def test_sign_ethereum_transactions(self) -> None:
        chain_id = 1
        request = SignEthereumTransactionsRequest(
            transactions=[
                EthereumTxParams(
                    value=1,
                    chainId=chain_id,
                    gas=100000,
                    gasPrice=4,
                    nonce=5,
                    toAddress=MOCK_ETHEREUM_ADDRESS,
                    data=b"",
                    fromAddress=MOCK_ETHEREUM_ADDRESS,
                )
            ]
        )
        response = self.servicer.SignEthereumTransactions(request)
        self.assertEqual(len(response.transactions), 1, "should be one signed transaction")
        transaction = response.transactions[0]
        self.assertEqual(
            MOCK_ETHEREUM_ADDRESS,
            Account.recover_transaction(serialized_transaction=transaction),  # pylint: disable=no-value-for-parameter
        )


class TestSignBitcoinTransactions(TestServicerBase):
    def setUp(self) -> None:
        super().setUp()
        with self._session_factory as session:
            key = Key(
                key_uuid=MOCK_SECP256K1_KEY_UUID,
                private_key=MOCK_SECP256K1_PRIVATE_KEY,
            )
            session.add(key)
            session.commit()

    def test_sign_bitcoin_transactions(self) -> None:
        request = SignBitcoinTransactionsRequest(
            transactions=[
                SignBitcoinTransactionsRequest.TransactionRequest(
                    vinKeyIds=[MOCK_SECP256K1_KEY_UUID.bytes, MOCK_SECP256K1_KEY_UUID.bytes],
                    txParams=BitcoinTxParams(
                        sources=[
                            BitcoinTransactionSource(
                                txid=bytes.fromhex("e2dccb4a6c5a4c770fe3db82179e2689cb0f8fb1ff435ab4c638d2d6228a6f39"),
                                vout=0,
                            ),
                            BitcoinTransactionSource(
                                txid=bytes.fromhex("8cf706c8e445d35713a48a6a2ac5fe4562b126d0d82ed012aa0d5dc5d933fec1"),
                                vout=1,
                            ),
                        ],
                        destinations=[
                            BitcoinTransactionDestination(toAddress=MOCK_BITCOIN_ADDRESS, value="100"),
                            BitcoinTransactionDestination(toAddress=MOCK_BITCOIN_ADDRESS, value="200"),
                        ],
                    ),
                )
            ]
        )
        response = self.servicer.SignBitcoinTransactions(request)
        self.assertEqual(len(response.transactions), 1, "should be one signed transaction")
        transaction = response.transactions[0]
        tx = CMutableTransaction.deserialize(transaction)
        for i, txin in enumerate(tx.vin):
            key_uuid = uuid.UUID(bytes=request.transactions[0].vinKeyIds[i])
            with self._session_factory as session:
                key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
                script_pub_key = CBitcoinAddress(key.bitcoin_address).to_scriptPubKey()
            VerifyScript(txin.scriptSig, script_pub_key, tx, i, (SCRIPT_VERIFY_P2SH,))


if __name__ == "__main__":
    unittest.main()
