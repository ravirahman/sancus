import uuid


def generate_uuid4() -> uuid.UUID:
    return _generate_uuid4()


def _generate_uuid4() -> uuid.UUID:
    # Defined as a private method for easy monkeypatching
    return uuid.uuid4()


def bytes_to_uuid(data: bytes) -> uuid.UUID:
    return uuid.UUID(bytes=data.rjust(16, b"\0"))
