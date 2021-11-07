import unittest
import uuid

from common.constants import (
    ADMIN_UUID,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
    Currency,
)
from common.utils.uuid import generate_uuid4
from common.utils.zk.bit_commitment import verify_bit_commitment
from common.utils.zk.key_permutation import permute_private_key, verify_key_permutation
from petlib.bn import Bn
from protobufs.account_pb2 import AccountType
from protobufs.institution.account_pb2 import KeyType

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.sql.key_currency_account import KeyCurrencyAccount
from tests.base import BaseBackendTestCase
from tests.fixtures import MOCK_USER_UUID


class TestKeyClient(BaseBackendTestCase):
    backend: Backend

    def setUp(self) -> None:
        super().setUp()
        with self.backend.sessionmaker() as session:
            # add an ethereum account
            eth_account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.ETH,
                account_type=AccountType.DEPOSIT_ACCOUNT,
            )
            session.add(eth_account)
            session.commit()
            self.eth_account_uuid = eth_account.uuid

    def validate_key(self, key: Key) -> None:
        # first verify the key permutation. Not really necessary as this is done in the audit.
        nizk = key.permutation_nizk
        permuted_public_key = key.permuted_secp256k1_public_key
        public_key = key.secp256k1_public_key
        permuted_private_key = key.permuted_private_key
        if key.key_type != KeyType.ANONYMOUS:
            self.assertIsNotNone(permuted_private_key)
            self.assertEqual(permuted_public_key, permuted_private_key * SECP256K1_GENERATOR)

        private_key = key.private_key
        if key.key_type == KeyType.HOT:
            self.assertIsNotNone(private_key)
            self.assertEqual(permuted_private_key * public_key, private_key * permuted_public_key)

        ownership_commitment = (
            Bn(key.ownership_s) * key.permuted_secp256k1_public_key + key.ownership_r * SECP256K1_ALTERNATIVE_GENERATOR
        )
        verify_bit_commitment(ownership_commitment, key.permuted_secp256k1_public_key, key.ownership_nizk)

        verify_key_permutation(public_key, permuted_public_key, nizk)

    def validate_ownership_commitment(
        self, key: Key, key_account_commitment: KeyAccountCommitment, deposits_will_be_credited_to_account_for_key: bool
    ) -> None:
        # then verify the key commitment. Not really necessary as this is done in the audit.
        s = key_account_commitment.s
        r = key_account_commitment.r
        self.assertEqual(s, deposits_will_be_credited_to_account_for_key)

        nizk = key_account_commitment.nizk

        permuted_public_key = key.permuted_secp256k1_public_key

        commitment = s * permuted_public_key + r * SECP256K1_ALTERNATIVE_GENERATOR
        verify_bit_commitment(commitment, permuted_public_key, nizk)

    def test_make_new_hot_key(self) -> None:
        key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            self.assertEqual(key.key_type, KeyType.HOT)
            self.validate_key(key)

            key_currency_accounts = (
                session.query(KeyCurrencyAccount).filter(KeyCurrencyAccount.key_uuid == key_uuid).all()
            )
            num_currencies = len(Currency)
            self.assertEqual(len(key_currency_accounts), num_currencies)

    def test_import_hot_key(self) -> None:
        private_key = SECP256K1_ORDER.random()
        key_uuid = self.backend.key_client.import_hot_key(private_key)
        with self.backend.sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            self.assertEqual(key.key_type, KeyType.HOT)
            self.validate_key(key)

            key_currency_accounts = (
                session.query(KeyCurrencyAccount).filter(KeyCurrencyAccount.key_uuid == key_uuid).all()
            )
            num_currencies = len(Currency)
            self.assertEqual(len(key_currency_accounts), num_currencies)
            for kca in key_currency_accounts:
                self.assertEqual(kca.account_uuid, ADMIN_UUID)

    def test_add_anonymous_key(self) -> None:
        public_key = SECP256K1_ORDER.random() * SECP256K1_GENERATOR
        key_uuid = self.backend.key_client.add_anonymous_key(public_key)
        with self.backend.sessionmaker() as session:
            # this key should have an entry in KeyCurrencyAccount, Key, and PermutedKey
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            self.assertEqual(key.key_type, KeyType.ANONYMOUS)
            self.validate_key(key)

            key_currency_accounts = (
                session.query(KeyCurrencyAccount).filter(KeyCurrencyAccount.key_uuid == key_uuid).all()
            )
            num_currencies = len(Currency)
            self.assertEqual(len(key_currency_accounts), num_currencies)
            for kca in key_currency_accounts:
                self.assertIsNone(kca.account_uuid)
                self.assertIsNone(kca.available_balance)
                self.assertIsNone(kca.approximate_available_balance)

    def test_add_cold_key(self) -> None:
        key_uuid = generate_uuid4()
        private_key = SECP256K1_ORDER.random()
        public_key = private_key * SECP256K1_GENERATOR
        k = SECP256K1_ORDER.random()
        permuted_private_key, nizk = permute_private_key(private_key, k)
        self.backend.key_client.add_cold_key(key_uuid, public_key, permuted_private_key, nizk)
        with self.backend.sessionmaker() as session:
            # this key should have an entry in KeyCurrencyAccount, Key, and PermutedKey
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            self.assertEqual(key.key_type, KeyType.COLD)
            self.validate_key(key)

            key_currency_accounts = (
                session.query(KeyCurrencyAccount).filter(KeyCurrencyAccount.key_uuid == key_uuid).all()
            )
            num_currencies = len(Currency)
            self.assertEqual(len(key_currency_accounts), num_currencies)

    def test_assign_key_as_decoy_to_account(self) -> None:
        key_uuid = self.backend.key_client.make_new_hot_key()
        self.backend.key_client.assign_key_as_decoy_to_account(key_uuid=key_uuid, account_uuid=self.eth_account_uuid)
        with self.backend.sessionmaker() as session:
            # validate the decoy proof
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            key_account_commitment = (
                session.query(KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.key_uuid == key_uuid,
                    KeyAccountCommitment.account_uuid == self.eth_account_uuid,
                )
                .one()
            )
            self.validate_ownership_commitment(
                key,
                key_account_commitment,
                deposits_will_be_credited_to_account_for_key=False,
            )

    def test_assign_key_for_deposits_to_account(self) -> None:
        key_uuid = self.backend.key_client.make_new_hot_key()
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=key_uuid, account_uuid=self.eth_account_uuid
        )
        with self.backend.sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            key_account_commitment = (
                session.query(KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.key_uuid == key_uuid,
                    KeyAccountCommitment.account_uuid == self.eth_account_uuid,
                )
                .one()
            )
            self.validate_ownership_commitment(
                key,
                key_account_commitment,
                deposits_will_be_credited_to_account_for_key=True,
            )

            key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(key_currency.account_uuid, self.eth_account_uuid)

    def test_find_or_create_key_and_assign_to_account(self) -> None:
        hot_key_uuid = self.backend.key_client.make_new_hot_key()
        anonymous_key_uuid = self.backend.key_client.add_anonymous_key(SECP256K1_ORDER.random() * SECP256K1_GENERATOR)

        def add_cold_key() -> uuid.UUID:
            cold_key_uuid = generate_uuid4()
            private_key = SECP256K1_ORDER.random()
            public_key = private_key * SECP256K1_GENERATOR
            k = SECP256K1_ORDER.random()
            permuted_private_key, nizk = permute_private_key(private_key, k)

            self.backend.key_client.add_cold_key(
                cold_key_uuid,
                public_key,
                permuted_private_key,
                nizk,
            )
            return cold_key_uuid

        cold_key_uuid = add_cold_key()
        with self.backend.sessionmaker() as session:
            self.assertEqual(
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == hot_key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .update({KeyCurrencyAccount.pending_admin_deposits: 1}),
                1,
            )
            session.commit()

        first_key_uuid = self.backend.key_client.find_or_create_key_and_assign_to_account(self.eth_account_uuid)
        self.assertEqual(first_key_uuid, cold_key_uuid)
        with self.backend.sessionmaker() as session:
            first_key = session.query(Key).filter(Key.key_uuid == first_key_uuid).one()
            first_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == first_key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(first_key_currency.account_uuid, self.eth_account_uuid)

            key_account_commitment = (
                session.query(KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.key_uuid == first_key_uuid,
                    KeyAccountCommitment.account_uuid == self.eth_account_uuid,
                )
                .one()
            )
            self.validate_ownership_commitment(first_key, key_account_commitment, True)

        second_key_uuid = self.backend.key_client.find_or_create_key_and_assign_to_account(self.eth_account_uuid)
        self.assertNotIn(second_key_uuid, [hot_key_uuid, cold_key_uuid, anonymous_key_uuid])
        with self.backend.sessionmaker() as session:
            second_key = session.query(Key).filter(Key.key_uuid == second_key_uuid).one()
            second_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == second_key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(second_key_currency.account_uuid, self.eth_account_uuid)

            key_account_commitment = (
                session.query(KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.key_uuid == second_key_uuid,
                    KeyAccountCommitment.account_uuid == self.eth_account_uuid,
                )
                .one()
            )
            self.validate_ownership_commitment(second_key, key_account_commitment, True)

        with self.backend.sessionmaker() as session:
            # the three original keys plus the new one for second_key_uuid
            self.assertEqual(session.query(Key).count(), 4)


if __name__ == "__main__":
    unittest.main()
