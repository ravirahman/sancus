import uuid
from decimal import Decimal

import petlib.ec
from common.constants import CURRENCY_TO_BLOCKCHAIN, Blockchain, Currency
from common.utils.zk import NIZK
from common.utils.zk.bit_commitment import verify_bit_commitment
from common.utils.zk.key_permutation import verify_key_permutation
from sqlalchemy.orm import Session

from auditor.sql.blockchain_address_key import BlockchainAddressKey
from auditor.sql.key import Key
from auditor.sql.key_account_commitment import KeyAccountCommitment
from auditor.sql.key_currency_block import KeyCurrencyBlock
from auditor.utils.blockchain_client.client import BlockchainClient


class KeyClient:
    def __init__(self, blockchain_client: BlockchainClient) -> None:
        self._blockchain_client = blockchain_client

    def track_deposit_key(
        self,
        session: Session,
        key_uuid: uuid.UUID,
        public_key: petlib.ec.EcPt,
        permuted_public_key: petlib.ec.EcPt,
        permutation_nizk: NIZK,
        ownership_commitment: petlib.ec.EcPt,
        ownership_nizk: NIZK,
        audit_version: int,
    ) -> None:
        has_key = session.query(Key).filter(Key.key_uuid == key_uuid).count() > 0
        if has_key:
            raise ValueError(f"key_uuid({key_uuid}) already imported")
        # verify the nizk
        verify_key_permutation(public_key, permuted_public_key, permutation_nizk)
        key = Key(
            key_uuid=key_uuid,
            secp256k1_public_key=public_key,
            permuted_secp256k1_public_key=permuted_public_key,
            permutation_nizk=permutation_nizk,
            audit_publish_version=audit_version,
            ownership_commitment=ownership_commitment,
            ownernship_nzik=ownership_nizk,
        )
        session.add(key)
        for blockchain in Blockchain:
            session.add(
                BlockchainAddressKey(
                    blockchain=blockchain,
                    address=key.get_address(blockchain),
                    key_uuid=key.key_uuid,
                )
            )
        for currency in Currency:
            block_number = self._blockchain_client.get_latest_processed_block_number(CURRENCY_TO_BLOCKCHAIN[currency])
            if block_number is None:
                block_number = self._blockchain_client.get_start_block_number(CURRENCY_TO_BLOCKCHAIN[currency]) - 1
            session.add(
                KeyCurrencyBlock(
                    key_uuid=key_uuid,
                    currency=currency,
                    block_number=block_number,
                    cumulative_tracked_withdrawal_amount=Decimal("0"),
                    cumulative_tracked_deposit_amount=Decimal("0"),
                )
            )

    @staticmethod
    def track_deposit_key_account(  # type: ignore[misc]
        session: Session,
        key_uuid: uuid.UUID,
        account_uuid: uuid.UUID,
        ownership_commitment: petlib.ec.EcPt,
        ownership_nizk: NIZK,
        block_number: int,
        audit_version: int,
    ) -> None:
        does_key_account_commitment_exist = (
            session.query(KeyAccountCommitment)
            .filter(KeyAccountCommitment.key_uuid == key_uuid, KeyAccountCommitment.account_uuid == account_uuid)
            .count()
            > 0
        )
        if does_key_account_commitment_exist:
            raise ValueError(f"key_uuid({key_uuid}), account_uuid({account_uuid}) already has a commitment")
        key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
        verify_bit_commitment(ownership_commitment, key.permuted_secp256k1_public_key, ownership_nizk)
        session.add(
            KeyAccountCommitment(
                key_uuid=key_uuid,
                account_uuid=account_uuid,
                block_number=block_number,
                commitment=ownership_commitment,
                nizk=ownership_nizk,
                audit_publish_version=audit_version,
            )
        )
