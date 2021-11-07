import unittest

import grpc
import petlib.bn
from common.constants import Currency
from common.utils.datetime import datetime_to_protobuf, get_current_datetime
from common.utils.uuid import bytes_to_uuid, generate_uuid4
from google.protobuf.timestamp_pb2 import Timestamp
from protobufs.account_pb2 import AccountType
from protobufs.institution.deposit_pb2 import (
    ListDepositKeysRequest,
    MakeDepositKeyRequest,
)
from protobufs.institution.deposit_pb2_grpc import DepositStub

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.key_account_commitment import KeyAccountCommitment
from tests.base import BaseBackendTestCase
from tests.fixtures import MOCK_ACCOUNT_UUID, MOCK_USER_UUID


class TestDeposit(BaseBackendTestCase):
    deposit_stub: DepositStub
    channel: grpc.Channel
    backend: Backend

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.deposit_stub = DepositStub(cls.channel)

    def setUp(self) -> None:
        super().setUp()
        with self.backend.sessionmaker() as session:
            account = Account(
                account_type=AccountType.DEPOSIT_ACCOUNT,
                uuid=MOCK_ACCOUNT_UUID,
                user_uuid=MOCK_USER_UUID,
                currency=Currency.GUSD,
            )
            session.add(account)
            self.account_uuid = account.uuid
            session.commit()
        self.key_uuid = self.backend.key_client.make_new_hot_key()

    def test_make_deposit_key(self) -> None:
        request = MakeDepositKeyRequest(accountId=MOCK_ACCOUNT_UUID.bytes)
        response = self.deposit_stub.MakeDepositKey(request)
        self.assertEqual(petlib.bn.Bn.from_decimal(response.depositKey.ownershipCommitment.x), petlib.bn.Bn(1))
        address = response.depositKey.address

        # doing a second request to force on-the-fly generation of a new hot key
        response_2 = self.deposit_stub.MakeDepositKey(request)
        address_2 = response_2.depositKey.address
        self.assertEqual(petlib.bn.Bn.from_decimal(response_2.depositKey.ownershipCommitment.x), petlib.bn.Bn(1))
        self.assertNotEqual(address, address_2)

    def test_make_deposit_key_2(self) -> None:
        with self.backend.sessionmaker() as session:
            account_2_uuid = generate_uuid4()
            account_2 = Account(
                account_type=AccountType.DEPOSIT_ACCOUNT,
                uuid=account_2_uuid,
                user_uuid=MOCK_USER_UUID,
                currency=Currency.ETH,
            )
            session.add(account_2)
            session.commit()
        request = MakeDepositKeyRequest(accountId=MOCK_ACCOUNT_UUID.bytes)
        response = self.deposit_stub.MakeDepositKey(request)
        self.assertEqual(petlib.bn.Bn.from_decimal(response.depositKey.ownershipCommitment.x), petlib.bn.Bn(1))

        request = MakeDepositKeyRequest(accountId=account_2_uuid.bytes)
        response = self.deposit_stub.MakeDepositKey(request)
        self.assertEqual(petlib.bn.Bn.from_decimal(response.depositKey.ownershipCommitment.x), petlib.bn.Bn(1))

    def test_make_deposit_key_decoy(self) -> None:
        with self.backend.sessionmaker() as session:
            account_2_uuid = generate_uuid4()
            account_2 = Account(
                account_type=AccountType.DEPOSIT_ACCOUNT,
                uuid=account_2_uuid,
                user_uuid=MOCK_USER_UUID,
                currency=Currency.GUSD,
            )
            session.add(account_2)
            session.commit()
        request = MakeDepositKeyRequest(accountId=MOCK_ACCOUNT_UUID.bytes)
        response = self.deposit_stub.MakeDepositKey(request)
        self.assertEqual(petlib.bn.Bn.from_decimal(response.depositKey.ownershipCommitment.x), petlib.bn.Bn(1))
        with self.backend.sessionmaker() as session:
            decoy_commitment = (
                session.query(KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.key_uuid == bytes_to_uuid(response.depositKey.keyId),
                    KeyAccountCommitment.account_uuid == account_2_uuid,
                )
                .one()
            )
            self.assertFalse(decoy_commitment.s)

    def test_list_deposit_keys(self) -> None:
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=self.key_uuid,
            account_uuid=self.account_uuid,
        )
        from_timestamp = Timestamp(seconds=0, nanos=0)
        to_timestamp = datetime_to_protobuf(get_current_datetime())
        request = ListDepositKeysRequest(
            request=ListDepositKeysRequest.Request(
                accountId=MOCK_ACCOUNT_UUID.bytes,
                fromTimestamp=from_timestamp,
                toTimestamp=to_timestamp,
            )
        )
        response = self.deposit_stub.ListDepositKeys(request)
        self.assertEqual(len(response.response), 1)
        self.assertEqual(petlib.bn.Bn.from_decimal(response.response[0].ownershipCommitment.x), petlib.bn.Bn(1))

        req2 = ListDepositKeysRequest(nextToken=response.nextToken)
        resp2 = self.deposit_stub.ListDepositKeys(req2)
        self.assertEqual(len(resp2.response), 0)
        self.assertEqual(resp2.nextToken, "")


if __name__ == "__main__":
    unittest.main()
