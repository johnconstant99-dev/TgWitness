from ..access import Console
from ..proxy_catalog import ProxyPool
from ..proxy_catalog import PublicCatalog
from .access import AccessOperations
from .access import authenticate, identify as identify_request
from .accounts import AccountsOperations
from .chats import ChatsOperations
from .cloud import CloudOperations
from .documentation import DocumentationOperations
from .evidence import EvidenceOperations
from .export import ExportOperations
from .lifecycle import LifecycleOperations
from .network import NetworkOperations
from .system import SystemOperations
from pathlib import Path
from fastapi import Depends, Request
import asyncio


class ApplicationContext(
    LifecycleOperations,
    SystemOperations,
    AccessOperations,
    AccountsOperations,
    CloudOperations,
    NetworkOperations,
    ChatsOperations,
    EvidenceOperations,
    DocumentationOperations,
    ExportOperations,
):
    def __init__(
        self,
        data_dir=None,
        demo=False,
        client_factory=None,
        token_override=None,
        allow_profiles=True,
        account_guard=None,
        proxy_pool=None,
        access=None,
        profile_id="default",
    ):
        self.data_dir = data_dir
        self.demo = demo
        self.client_factory = client_factory
        self.token_override = token_override
        self.allow_profiles = allow_profiles
        self.account_guard = account_guard
        self.proxy_pool = proxy_pool
        self.access = access
        self.profile_id = profile_id
        self.root = Path(self.data_dir or "data").resolve()
        self.op_lock = asyncio.Lock()
        self.export_lock = asyncio.Lock()
        self.action_tasks = set()
        self.qr_access_session = None
        self.qr_access_candidate = None
        self.prepared_chat_exports = {}
        self.public_proxies = PublicCatalog(self.root)
        self.shared_pool = self.proxy_pool or ProxyPool(self.public_proxies)
        self.public_proxies = self.shared_pool.catalog
        self.console = None if self.access else Console()

    async def identify(self, request, credential):
        return await identify_request(request, credential, ctx=self)

    async def authenticate(self, request: Request, principal=Depends(identify_request)):
        return await authenticate(request, principal, ctx=self)
