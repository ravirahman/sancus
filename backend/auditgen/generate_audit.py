import logging
import os
import tarfile
from types import TracebackType
from typing import TYPE_CHECKING, Callable, Optional, Type, TypeVar, cast

import grpc
import web3
from common.constants import ADMIN_UUID
from common.utils.grpc_channel import make_grpc_channel
from common.utils.ipfs_client import IPFSClient
from common.utils.managed_thread_pool import ManagedThreadPool
from google.protobuf.message import Message
from protobufs.institution.auditGen_pb2 import (
    FinalizeAuditRequest,
    GenerateAuditRequest,
)
from protobufs.institution.auditGen_pb2_grpc import AuditGenStub
from protobufs.institution.auditGenAccount_pb2 import (
    AddAccountToAuditRequest,
    ListAccountsNotInAuditRequest,
    ListAccountsNotInAuditResponse,
)
from protobufs.institution.auditGenAccount_pb2_grpc import AuditGenAccountStub
from protobufs.institution.auditGenAccountDeltaGroup_pb2 import (
    AddAccountDeltaGroupToAuditRequest,
    ListAccountDeltaGroupsNotInAuditRequest,
    ListAccountDeltaGroupsNotInAuditResponse,
)
from protobufs.institution.auditGenAccountDeltaGroup_pb2_grpc import (
    AuditGenAccountDeltaGroupStub,
)
from protobufs.institution.auditGenKey_pb2 import (
    AddKeyToAuditRequest,
    ListKeysNotInAuditRequest,
    ListKeysNotInAuditResponse,
)
from protobufs.institution.auditGenKey_pb2_grpc import AuditGenKeyStub
from protobufs.institution.auditGenKeyAccount_pb2 import (
    AddKeyAccountToAuditRequest,
    ListKeyAccountsNotInAuditRequest,
    ListKeyAccountsNotInAuditResponse,
)
from protobufs.institution.auditGenKeyAccount_pb2_grpc import AuditGenKeyAccountStub
from protobufs.institution.auditGenKeyAccountLiability_pb2 import (
    AddKeyAccountLiabilityToAuditRequest,
    ListKeyAccountLiabilitiesNotInAuditRequest,
    ListKeyAccountLiabilitiesNotInAuditResponse,
)
from protobufs.institution.auditGenKeyAccountLiability_pb2_grpc import (
    AuditGenKeyAccountLiabilityStub,
)
from protobufs.institution.auditGenKeyCurrencyAsset_pb2 import (
    AddKeyCurrencyAssetToAuditRequest,
    ListKeyCurrencyAssetsNotInAuditRequest,
    ListKeyCurrencyAssetsNotInAuditResponse,
)
from protobufs.institution.auditGenKeyCurrencyAsset_pb2_grpc import (
    AuditGenKeyCurrencyAssetStub,
)
from protobufs.institution.auditGenUserCumulativeLiability_pb2 import (
    AddUserCumulativeLiabilityToAuditRequest,
    ListUserCumulativeLiabilitiesNotInAuditRequest,
    ListUserCumulativeLiabilitiesNotInAuditResponse,
)
from protobufs.institution.auditGenUserCumulativeLiability_pb2_grpc import (
    AuditGenUserCumulativeLiabilityStub,
)
from protobufs.institution.auditGenUserKey_pb2 import (
    AddUserKeyToAuditRequest,
    ListUserKeysNotInAuditRequest,
    ListUserKeysNotInAuditResponse,
)
from protobufs.institution.auditGenUserKey_pb2_grpc import AuditGenUserKeyStub
from web3.gas_strategies.rpc import rpc_gas_price_strategy

from auditgen.config import AuditGenConfig
from backend.utils.jwt_client import JWTClient
from backend.utils.list_rpc import list_rpc_yield
from backend.utils.profilers import record_file_size, record_latency

if TYPE_CHECKING:
    from concurrent.futures import Future  # pylint: disable=ungrouped-imports
    from typing import List  # pylint: disable=ungrouped-imports

TRequest = TypeVar("TRequest", bound=Message)
TResponse = TypeVar("TResponse", bound=Message)

LOGGER = logging.getLogger(__name__)

with open(os.path.join(os.path.dirname(__file__), "audit_publisher_abi.json"), "r") as audit_publisher_abi_f:
    AUDIT_PUBLISHER_ABI = audit_publisher_abi_f.read()


def _write_protobuf_to_file(output_message: Message, outfile_name: str) -> None:
    with open(outfile_name, "wb") as f:
        f.write(output_message.SerializeToString())
    record_file_size(outfile_name)


def _call_and_save_result(
    request: TRequest,
    handler: Callable[[TRequest], TResponse],
    outfile_name: str,
    field_to_save: str,
    skip_failed_precondition: bool = False,
) -> Optional[TResponse]:
    LOGGER.info("Calling RPC for output file %s", outfile_name)
    while True:
        try:
            response = handler(request)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.ABORTED:
                LOGGER.info(
                    "Repeating RPC for file %s as we received an aborted",
                    outfile_name,
                    exc_info=True,
                )
                # try again
                continue
            if skip_failed_precondition and e.code() == grpc.StatusCode.FAILED_PRECONDITION:
                LOGGER.info(
                    "Skipping RPC error for output file %s since skip_failed_precondition is True",
                    outfile_name,
                    exc_info=True,
                )
                return None
            raise e
        else:
            LOGGER.info("Successfully generated audit file %s", outfile_name)
            _write_protobuf_to_file(getattr(response, field_to_save), outfile_name)
            return response


class AuditGen:
    def __init__(self, config: AuditGenConfig) -> None:
        jwt_client = JWTClient(config.jwt_config)
        admin_jwt = jwt_client.issue_auth_jwt(ADMIN_UUID)
        self.channel = make_grpc_channel(config.grpc_config, admin_jwt)
        self.audit_gen = AuditGenStub(self.channel)
        self.audit_gen_user_key = AuditGenUserKeyStub(self.channel)
        self.audit_gen_key = AuditGenKeyStub(self.channel)
        self.audit_gen_account = AuditGenAccountStub(self.channel)
        self.audit_gen_key_account = AuditGenKeyAccountStub(self.channel)
        self.audit_gen_account_delta_group = AuditGenAccountDeltaGroupStub(self.channel)
        self.audit_gen_key_account_liability = AuditGenKeyAccountLiabilityStub(self.channel)
        self.audit_gen_key_currency_asset = AuditGenKeyCurrencyAssetStub(self.channel)
        self.audit_gen_user_cumulative_liability = AuditGenUserCumulativeLiabilityStub(self.channel)
        self.ipfs_client = IPFSClient(config.ipfs_config)
        w3 = web3.Web3(provider=config.w3_config.provider, middlewares=config.w3_config.middlewares)
        w3.eth.setGasPriceStrategy(rpc_gas_price_strategy)
        self._w3 = w3
        self._audit_owner = config.audit_publisher_address
        self._audit_publisher_contract = self._w3.eth.contract(
            address=config.audit_smart_contract_address, abi=AUDIT_PUBLISHER_ABI
        )
        self._managed_thread_pool = ManagedThreadPool(config.grpc_config.max_workers)

    def _call_and_save_result_tp(
        self,
        request: TRequest,
        handler: Callable[[TRequest], TResponse],
        outfile_name: str,
        field_to_save: str,
        skip_failed_precondition: bool = False,
    ) -> None:
        def bound_call_and_save_result() -> None:
            _call_and_save_result(request, handler, outfile_name, field_to_save, skip_failed_precondition)

        self._managed_thread_pool(bound_call_and_save_result)

    def __enter__(self) -> "AuditGen":
        return self

    def close(self) -> None:
        self.ipfs_client.close()

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        self.close()

    @record_latency
    def add_accounts_to_audit(  # type: ignore[misc]
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListAccountsNotInAuditRequest()
        with self._managed_thread_pool:
            for account in list_rpc_yield(list_request, self.audit_gen_account.ListAccountsNotInAudit):
                assert isinstance(account, ListAccountsNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddAccountToAuditRequest(accountId=account.accountId, auditVersion=audit_version),
                    self.audit_gen_account.AddAccountToAudit,
                    os.path.join(audit_folder, "accounts", account.accountId.hex() + ".bin"),
                    "account",
                )

    @record_latency
    def add_user_keys_to_audit(  # type: ignore[misc]
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListUserKeysNotInAuditRequest()
        with self._managed_thread_pool:
            for user_key in list_rpc_yield(list_request, self.audit_gen_user_key.ListUserKeysNotInAudit):
                assert isinstance(user_key, ListUserKeysNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddUserKeyToAuditRequest(keyId=user_key.userKeyId, auditVersion=audit_version),
                    self.audit_gen_user_key.AddUserKeyToAudit,
                    os.path.join(audit_folder, "user_keys", user_key.userKeyId.hex() + ".bin"),
                    "userKey",
                )

    @record_latency
    def add_keys_to_audit(  # type: ignore[misc]
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListKeysNotInAuditRequest()
        with self._managed_thread_pool:
            for key in list_rpc_yield(list_request, self.audit_gen_key.ListKeysNotInAudit):
                assert isinstance(key, ListKeysNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddKeyToAuditRequest(keyId=key.keyId, auditVersion=audit_version),
                    self.audit_gen_key.AddKeyToAudit,
                    os.path.join(audit_folder, "keys", key.keyId.hex() + ".bin"),
                    "key",
                )

    @record_latency
    def add_key_accounts_to_audit(  # type: ignore[misc]
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListKeyAccountsNotInAuditRequest()
        with self._managed_thread_pool:
            for key_account in list_rpc_yield(list_request, self.audit_gen_key_account.ListKeyAccountsNotInAudit):
                assert isinstance(key_account, ListKeyAccountsNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddKeyAccountToAuditRequest(
                        keyId=key_account.keyId, accountId=key_account.accountId, auditVersion=audit_version
                    ),
                    self.audit_gen_key_account.AddKeyAccountToAudit,
                    os.path.join(
                        audit_folder,
                        "key_accounts",
                        key_account.keyId.hex() + "-" + key_account.accountId.hex() + ".bin",
                    ),
                    "keyAccount",
                    skip_failed_precondition=True,
                )

    @record_latency
    def add_account_delta_groups_to_audit(  # type: ignore[misc]
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListAccountDeltaGroupsNotInAuditRequest()
        with self._managed_thread_pool:
            for account_delta_group in list_rpc_yield(
                list_request, self.audit_gen_account_delta_group.ListAccountDeltaGroupsNotInAudit
            ):
                assert isinstance(account_delta_group, ListAccountDeltaGroupsNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddAccountDeltaGroupToAuditRequest(
                        accountDeltaGroupId=account_delta_group.accountDeltaGroupId, auditVersion=audit_version
                    ),
                    self.audit_gen_account_delta_group.AddAccountDeltaGroupToAudit,
                    os.path.join(
                        audit_folder, "account_delta_groups", account_delta_group.accountDeltaGroupId.hex() + ".bin"
                    ),
                    "accountDeltaGroup",
                    skip_failed_precondition=True,
                )

    @record_latency
    def add_key_account_liabilities_to_audit(  # type: ignore[misc]
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListKeyAccountLiabilitiesNotInAuditRequest(
            request=ListKeyAccountLiabilitiesNotInAuditRequest.Request(
                auditVersion=audit_version,
            )
        )
        with self._managed_thread_pool:
            for key_account_liability in list_rpc_yield(
                list_request, self.audit_gen_key_account_liability.ListKeyAccountLiabilitiesNotInAudit
            ):
                assert isinstance(key_account_liability, ListKeyAccountLiabilitiesNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddKeyAccountLiabilityToAuditRequest(
                        keyId=key_account_liability.keyId,
                        accountId=key_account_liability.accountId,
                        auditVersion=audit_version,
                    ),
                    self.audit_gen_key_account_liability.AddKeyAccountLiabilityToAudit,
                    os.path.join(
                        audit_folder,
                        "key_account_liabilities",
                        key_account_liability.keyId.hex() + "-" + key_account_liability.accountId.hex() + ".bin",
                    ),
                    "keyAccountLiability",
                    skip_failed_precondition=True,
                )

    @record_latency
    def add_user_cumulative_liabilities_to_audit(  # type: ignore[misc]
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListUserCumulativeLiabilitiesNotInAuditRequest(
            request=ListUserCumulativeLiabilitiesNotInAuditRequest.Request(
                auditVersion=audit_version,
            )
        )
        with self._managed_thread_pool:
            for user_cumulative_liability in list_rpc_yield(
                list_request, self.audit_gen_user_cumulative_liability.ListUserCumulativeLiabilitiesNotInAudit
            ):
                assert isinstance(user_cumulative_liability, ListUserCumulativeLiabilitiesNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddUserCumulativeLiabilityToAuditRequest(
                        userId=user_cumulative_liability.userId,
                        auditVersion=audit_version,
                    ),
                    self.audit_gen_user_cumulative_liability.AddUserCumulativeLiabilityToAudit,
                    os.path.join(
                        audit_folder,
                        "user_cumulative_liability",
                        user_cumulative_liability.userId.hex() + ".bin",
                    ),
                    "userCumulativeLiability",
                )

    def add_key_currency_assets_to_audit(
        self,
        audit_folder: str,
        audit_version: int,
    ) -> None:
        list_request = ListKeyCurrencyAssetsNotInAuditRequest(
            request=ListKeyCurrencyAssetsNotInAuditRequest.Request(
                auditVersion=audit_version,
            )
        )
        with self._managed_thread_pool:
            for key_currency_asset in list_rpc_yield(
                list_request, self.audit_gen_key_currency_asset.ListKeyCurrencyAssetsNotInAudit
            ):
                assert isinstance(key_currency_asset, ListKeyCurrencyAssetsNotInAuditResponse.Response)
                self._call_and_save_result_tp(
                    AddKeyCurrencyAssetToAuditRequest(
                        keyId=key_currency_asset.keyId, currency=key_currency_asset.currency, auditVersion=audit_version
                    ),
                    self.audit_gen_key_currency_asset.AddKeyCurrencyAssetToAudit,
                    os.path.join(
                        audit_folder,
                        "key_currency_assets",
                        key_currency_asset.keyId.hex() + "-" + key_currency_asset.currency + ".bin",
                    ),
                    "keyCurrencyAsset",
                    skip_failed_precondition=True,
                )

    def publish_audit(self, output_directory: str) -> web3.types.TxReceipt:
        tarfile_name = os.path.join(output_directory, "audit.tgz")
        with tarfile.open(os.path.join(output_directory, "audit.tgz"), "x:gz") as f:
            f.add(os.path.join(output_directory, "audit"), arcname="audit", recursive=True)
        ipfs_cid = self.ipfs_client.upload(tarfile_name)
        tx_params = self._audit_publisher_contract.functions.log_audit(ipfs_cid.buffer).buildTransaction(
            {
                "from": self._audit_owner,
            }
        )
        txn_hash = self._w3.eth.send_transaction(tx_params)
        tx_receipt = cast(web3.types.TxReceipt, self._w3.eth.waitForTransactionReceipt(txn_hash))
        LOGGER.info(
            "Successfully published audit to %s; recorded in blockchain block %d with txn hash %s",
            ipfs_cid,
            tx_receipt.blockNumber,
            txn_hash.hex(),
        )
        return tx_receipt

    def generate_audit(self, output_directory: str) -> None:
        audit_folder = os.path.join(output_directory, "audit")
        os.mkdir(audit_folder)
        generate_audit_response = _call_and_save_result(
            GenerateAuditRequest(), self.audit_gen.GenerateAudit, os.path.join(audit_folder, "audit.bin"), "audit"
        )
        assert generate_audit_response is not None
        audit_version = generate_audit_response.audit.auditVersion
        audit_component_subdirs = [
            "user_keys",
            "keys",
            "accounts",
            "key_accounts",
            "account_delta_groups",
            "key_account_liabilities",
            "key_currency_assets",
            "user_cumulative_liability",
        ]
        for component in audit_component_subdirs:
            os.mkdir(os.path.join(audit_folder, component))

        self.add_keys_to_audit(audit_folder, audit_version)
        self.add_user_keys_to_audit(audit_folder, audit_version)
        self.add_accounts_to_audit(audit_folder, audit_version)
        self.add_key_accounts_to_audit(audit_folder, audit_version)
        self.add_key_currency_assets_to_audit(audit_folder, audit_version)
        self.add_key_account_liabilities_to_audit(audit_folder, audit_version)
        self.add_account_delta_groups_to_audit(audit_folder, audit_version)
        self.add_user_cumulative_liabilities_to_audit(audit_folder, audit_version)

        _call_and_save_result(
            FinalizeAuditRequest(auditVersion=audit_version),
            self.audit_gen.FinalizeAudit,
            os.path.join(audit_folder, "solvency_proof.bin"),
            "solvencyProof",
        )
        LOGGER.info("Finished audit for folder %s", output_directory)
