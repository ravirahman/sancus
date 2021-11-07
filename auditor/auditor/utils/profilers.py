import os
import threading
from csv import writer
from datetime import datetime
from typing import Any

from common.utils.datetime import get_current_datetime
from protobufs.audit_pb2 import Audit as AuditPB2


def write_latency_output_to_folder(
    output_dir: str, audit_version: int, start_time: datetime, end_time: datetime
) -> None:
    latency = end_time - start_time
    thread_id = threading.get_ident()

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    if not os.path.isfile(f"{output_dir}/thread_{thread_id}.csv"):
        with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
            writer_object = writer(f)
            writer_object.writerow(["audit_version", "start_time", "end_time", "latency"])

    with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
        writer_object = writer(f)
        writer_object.writerow([audit_version, start_time, end_time, latency])


def record_auditor_latency(handler: Any) -> Any:  # type: ignore[misc]
    profile_data_folder = os.environ.get("PROFILE_DATA_FOLDER")
    if profile_data_folder is None:
        return handler

    def wrapper(  # type: ignore[misc]
        self: Any,
        audit_tarfile: str,
    ) -> Any:
        audit_cid_hex = os.path.basename(audit_tarfile).split(".")[0]
        audit_parent_folder = os.path.join(self._audit_folder, audit_cid_hex)  # pylint: disable=protected-access
        self._safe_extract(audit_tarfile, audit_parent_folder)  # pylint: disable=protected-access
        audit_data_location = os.path.join(audit_parent_folder, "audit")
        audit_metadata_pb = self._load_protobuf_from_file(  # pylint: disable=protected-access
            AuditPB2, os.path.join(audit_data_location, "audit.bin")
        )

        start_time = get_current_datetime()
        resp = handler(self, audit_tarfile)
        end_time = get_current_datetime()

        output_dir = os.path.join(
            profile_data_folder, f"process_audit_{audit_metadata_pb.auditVersion}"  # type: ignore[arg-type]
        )
        write_latency_output_to_folder(output_dir, audit_metadata_pb.auditVersion, start_time, end_time)

        return resp

    return wrapper
