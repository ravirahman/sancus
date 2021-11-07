from common.sql.datetime import DateTime
from common.sql.protobuf import Protobuf
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from protobufs.webauthn_pb2 import AuthenticatorAssertionResponse, ChallengeRequest
from sqlalchemy import Column

from backend.sql.base import Base


class Challenge(Base):
    __tablename__ = "Challenge"

    uuid = Column(UUID, primary_key=True, default=generate_uuid4)
    challenge_request = Column(Protobuf(ChallengeRequest), nullable=False)
    authenticator_assertion_response = Column(Protobuf(AuthenticatorAssertionResponse))  # null if registration
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
    used_at = Column(DateTime)
    expiration = Column(DateTime, nullable=False)
