import uuid
from typing import Dict, List, Set

import petlib.bn
import petlib.ec
import zksk
from bitcoin.core import CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint
from bitcoin.core.script import SIGHASH_ALL, CScript, SignatureHash
from bitcoin.core.scripteval import SCRIPT_VERIFY_P2SH, VerifyScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret, P2PKHBitcoinAddress
from eth_account.account import Account
from eth_account.signers.local import LocalAccount
from eth_keys import KeyAPI
from eth_typing.encoding import HexStr
from eth_typing.evm import ChecksumAddress, HexAddress
from protobufs.institution.coldwallet_pb2 import (
    CreateKeyPairsRequest,
    CreateKeyPairsResponse,
    SignBitcoinTransactionsRequest,
    SignBitcoinTransactionsResponse,
    SignEthereumTransactionsRequest,
    SignEthereumTransactionsResponse,
)

from coldwallet.sql.models.key import Key
from coldwallet.utils.cm_scoped_session_factory import CMScopedSessionFactory
from coldwallet.utils.random_bn import generate_random_bn
from coldwallet.utils.uuid import bytes_to_uuid, generate_uuid4

SECP256K1_CURVE_ID = 714


class ColdWalletServicer:
    def __init__(self, cm_scoped_session_factory: CMScopedSessionFactory) -> None:
        self._session_factory = cm_scoped_session_factory

    def CreateKeyPairs(self, request: CreateKeyPairsRequest) -> CreateKeyPairsResponse:  # pylint: disable=invalid-name
        num_keys = request.numKeys
        public_keys: List[CreateKeyPairsResponse.Key] = []
        group = petlib.ec.EcGroup(nid=SECP256K1_CURVE_ID, optimize_mult=False)
        G = group.generator()
        with self._session_factory as session:
            for _ in range(num_keys):
                private_key = generate_random_bn(group.order())
                public_key = private_key * G
                key_id = generate_uuid4()
                # x = key.private_key
                # Y = x * G
                k = generate_random_bn(group.order())
                x_prime = k * private_key
                Y_prime = k * public_key  # pylint: disable=invalid-name
                k_s = zksk.Secret(name="k_s")
                stmt_1 = zksk.DLRep(Y_prime, k_s * public_key)
                zk_proof = stmt_1.prove({k_s: k})
                nizk = zk_proof.serialize()
                public_keys.append(
                    CreateKeyPairsResponse.Key(
                        keyId=key_id.bytes,
                        publicKey=public_key.export(),
                        permutedPrivateKey=x_prime.binary().rjust(32, b"\0"),
                        permutationNIZK=nizk,
                    )
                )
                session.add(
                    Key(
                        key_uuid=key_id,
                        private_key=private_key,
                    )
                )
            session.commit()
        return CreateKeyPairsResponse(publicKeys=public_keys)

    def SignEthereumTransactions(  # pylint: disable=invalid-name
        self, request: SignEthereumTransactionsRequest
    ) -> SignEthereumTransactionsResponse:
        ethereum_addresses: List[str] = []
        for transaction in request.transactions:
            ethereum_addresses.append(transaction.fromAddress)
        address_to_account: Dict[str, LocalAccount] = {}
        account = Account()
        with self._session_factory as session:
            keys = session.query(Key).filter(Key.ethereum_address.in_(ethereum_addresses)).all()
            for key in keys:
                private_key_bn = key.private_key
                assert isinstance(private_key_bn, petlib.bn.Bn)
                private_key = KeyAPI.PrivateKey(private_key_bn.binary().rjust(32, b"\0"))
                ethereum_address = ChecksumAddress(HexAddress(HexStr(key.ethereum_address)))
                address_to_account[ethereum_address] = LocalAccount(private_key, account)
        signed_transactions: List[bytes] = []
        for transaction in request.transactions:
            transaction_params = {
                "chainId": transaction.chainId,
                "data": transaction.data,
                "from": transaction.fromAddress,
                "gas": transaction.gas,
                "gasPrice": transaction.gasPrice,
                "nonce": transaction.nonce,
                "to": transaction.toAddress,
                "value": transaction.value,
            }
            signed_transaction = address_to_account[transaction.fromAddress].sign_transaction(transaction_params)
            signed_transactions.append(bytes(signed_transaction.rawTransaction))
        return SignEthereumTransactionsResponse(transactions=signed_transactions)

    def SignBitcoinTransactions(  # pylint: disable=invalid-name
        self, request: SignBitcoinTransactionsRequest
    ) -> SignBitcoinTransactionsResponse:
        key_uuids: Set[uuid.UUID] = set()
        for transaction_request in request.transactions:
            for vin_key_id in transaction_request.vinKeyIds:
                key_uuids.add(bytes_to_uuid(vin_key_id))
        key_uuid_to_account: Dict[uuid.UUID, CBitcoinSecret] = {}
        with self._session_factory as session:
            keys = session.query(Key).filter(Key.key_uuid.in_(key_uuids)).all()
        for key in keys:
            private_key_bn = key.private_key
            assert isinstance(private_key_bn, petlib.bn.Bn)
            private_key = CBitcoinSecret.from_secret_bytes(private_key_bn.binary().rjust(32, b"\0"))
            bitcoin_address = key.bitcoin_address
            assert isinstance(bitcoin_address, str)
            key_uuid_to_account[key.key_uuid] = private_key
        signed_transactions: List[bytes] = []
        for transaction_request in request.transactions:
            tx_ins: List[CMutableTxIn] = []
            tx_params = transaction_request.txParams
            for source in tx_params.sources:
                txid = source.txid
                vout = source.vout
                txin = CMutableTxIn(COutPoint(txid, vout))
                tx_ins.append(txin)
            tx_outs: List[CMutableTxOut] = []
            for destination in tx_params.destinations:
                tx_outs.append(
                    CMutableTxOut(destination.value, CBitcoinAddress(destination.toAddress).to_scriptPubKey())
                )
            tx = CMutableTransaction(tx_ins, tx_outs)
            for i, (key_id, source) in enumerate(zip(transaction_request.vinKeyIds, tx_params.sources)):
                key_uuid = bytes_to_uuid(key_id)
                seckey = key_uuid_to_account[key_uuid]
                from_address = P2PKHBitcoinAddress.from_pubkey(seckey.pub)
                txin_script_pub_key = from_address.to_scriptPubKey()
                sighash = SignatureHash(txin_script_pub_key, tx, i, SIGHASH_ALL)
                seckey = key_uuid_to_account[key_uuid]
                sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
                txin = tx.vin[i]
                txin.scriptSig = CScript([sig, seckey.pub])
                VerifyScript(txin.scriptSig, txin_script_pub_key, tx, i, (SCRIPT_VERIFY_P2SH,))
            signed_transactions.append(tx.serialize())
        return SignBitcoinTransactionsResponse(transactions=signed_transactions)
