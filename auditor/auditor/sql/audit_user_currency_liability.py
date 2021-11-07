import petlib.ec
from common.constants import SECP256K1_GROUP, Currency
from common.sql.ecpt import EcPt
from common.sql.enum import Enum
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from sqlalchemy import Column, Integer

from auditor.sql.base import Base


class AuditUserCurrencyLiability(Base):
    __tablename__ = "AuditUserCurrencyLiability"

    audit_version = Column(Integer, primary_key=True)
    user_uuid = Column(UUID, primary_key=True)
    currency = Column(Enum(Currency), primary_key=True)

    cumulative_deposit_commitment = Column(
        EcPt(SECP256K1_GROUP), nullable=False, default=petlib.ec.EcPt(SECP256K1_GROUP)
    )

    # should be set to the previous audit for the user
    cumulative_account_delta_commitment = Column(EcPt(SECP256K1_GROUP), nullable=False)

    to_currency_commitment = Column(EcPt(SECP256K1_GROUP))
    to_currency_nizk = Column(NIZK)
