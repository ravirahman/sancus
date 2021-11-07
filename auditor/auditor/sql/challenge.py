from common.sql.hex_string import HexString
from sqlalchemy import Column

from auditor.sql.base import Base


class Challenge(Base):
    __tablename__ = "Challenge"

    # we only care if the challenge is unique. Once we consume a challenge, record its nonce
    # so we can be sure that it will never be used again
    challenge_nonce = Column(HexString(64), primary_key=True)
