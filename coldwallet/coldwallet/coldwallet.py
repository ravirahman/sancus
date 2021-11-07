import argparse
from typing import List

from protobufs.institution.coldwallet_pb2 import DESCRIPTOR
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from coldwallet.servicer import ColdWalletServicer
from coldwallet.sql.base import Base
from coldwallet.utils.cm_scoped_session_factory import CMScopedSessionFactory

COLDWALLET_SERVICE = DESCRIPTOR.services_by_name["ColdWallet"]


class ColdWallet:
    def __init__(self, db_uri: str) -> None:
        engine = create_engine(db_uri, echo=False)
        Base.metadata.create_all(engine)
        session_factory = CMScopedSessionFactory(sessionmaker(bind=engine))
        self._servicer = ColdWalletServicer(session_factory)

    def handler(self, command: str, infile: str, outfile: str) -> None:
        method_descriptor = COLDWALLET_SERVICE.FindMethodByName(command)
        input_type = method_descriptor.input_type._concrete_class  # pylint: disable=protected-access
        input_message = input_type()
        with open(infile, "rb") as f:
            input_message.ParseFromString(f.read())

        output_message = getattr(self._servicer, command)(input_message)
        with open(outfile, "wb") as f:
            f.write(output_message.SerializeToString())

    @classmethod
    def cli(cls) -> None:
        method_names: List[str] = []
        for method in COLDWALLET_SERVICE.methods:
            method_names.append(method.name)
        parser = argparse.ArgumentParser()
        parser.add_argument("--database", type=str, required=True, help="URI to database")
        parser.add_argument(
            "command", type=str, help="Command to call. Must match a protobuf service name", choices=method_names
        )
        parser.add_argument("--in", type=str, help="Path to serialized protobuf describing request", dest="infile")
        parser.add_argument("--out", type=str, help="Outfile to generate", dest="outfile")
        args = parser.parse_args()
        ColdWallet(args.database).handler(args.command, args.infile, args.outfile)


if __name__ == "__main__":
    ColdWallet.cli()
