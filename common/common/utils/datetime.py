from datetime import datetime

import pytz
from google.protobuf.timestamp_pb2 import Timestamp


def get_current_datetime() -> datetime:
    return _get_current_datetime()


def _get_current_datetime() -> datetime:
    # Defined as a private method for easy monkeypatching
    return datetime.now(tz=pytz.UTC)


def datetime_to_protobuf(timestamp: datetime) -> Timestamp:
    timestamp_pb2 = Timestamp()
    timestamp_pb2.FromDatetime(timestamp)
    return timestamp_pb2


def protobuf_to_datetime(timestamp: Timestamp) -> datetime:
    return timestamp.ToDatetime().replace(tzinfo=pytz.UTC)
