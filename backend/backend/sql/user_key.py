from typing import TYPE_CHECKING

from common.sql.datetime import DateTime
from common.sql.protobuf import Protobuf
from common.sql.protobuf_enum import ProtobufEnum
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from protobufs.webauthn_pb2 import AuthenticatorAttestationResponse
from sqlalchemy import Column, Integer, LargeBinary

from backend.sql.base import Base

if TYPE_CHECKING:
    from protobufs.webauthn_pb2 import (  # pylint: disable=ungrouped-imports
        PublicKeyCredentialType,
    )


class UserKey(Base):
    __tablename__ = "UserKey"
    user_key_uuid = Column(UUID, primary_key=True, default=generate_uuid4)
    credential_id = Column(LargeBinary, nullable=False)
    user_uuid = Column(UUID, nullable=False, index=True)
    public_key = Column(LargeBinary, nullable=False)
    credential_type = Column(ProtobufEnum["PublicKeyCredentialType.V"], nullable=False)
    audit_publish_version = Column(Integer)
    add_to_audit_timestamp = Column(DateTime)
    attestation = Column(Protobuf(AuthenticatorAttestationResponse), nullable=False)
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
    sign_count = Column(Integer, default=0, nullable=False)
