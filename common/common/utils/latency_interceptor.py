import os
import threading
from csv import writer
from datetime import datetime
from typing import Any, Callable

import grpc
from grpc_interceptor import ServerInterceptor, parse_method_name

from common.utils.datetime import get_current_datetime


class LatencyInterceptor(ServerInterceptor):
    def intercept(  # type: ignore[misc, no-self-use]
        self,
        method: Callable,  # type: ignore[type-arg]
        request: Any,
        context: grpc.ServicerContext,
        method_name: str,
    ) -> Any:
        """
        Custom interceptor that measures the latency of a given RPC
        Returns: the result method(request, context) which is the RPC method response protobuf
        """

        def write_latency_output_to_folder(
            output_dir: str, method_name: str, start_time: datetime, end_time: datetime
        ) -> None:
            latency = end_time - start_time
            thread_id = threading.get_ident()
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir)
            if not os.path.isfile(f"{output_dir}/thread_{thread_id}.csv"):
                with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
                    writer_object = writer(f)
                    writer_object.writerow(["method_name", "start_time", "end_time", "latency"])
            with open(f"{output_dir}/thread_{thread_id}.csv", "a") as f:
                writer_object = writer(f)
                writer_object.writerow([method_name, start_time, end_time, latency])

        start_time = get_current_datetime()
        response = method(request, context)
        end_time = get_current_datetime()

        profile_data_folder = os.environ["PROFILE_DATA_FOLDER"]
        grpc_output_dir = os.path.join(profile_data_folder, "grpc_latency_output")

        write_latency_output_to_folder(grpc_output_dir, parse_method_name(method_name).method, start_time, end_time)

        return response
