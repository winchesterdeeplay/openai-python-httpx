# OpenAI Python bindings.
#
# Originally forked from the MIT-licensed Stripe Python bindings.

import os
import sys
from typing import TYPE_CHECKING, Optional

import httpx

if "pkg_resources" not in sys.modules:
    # workaround for the following:
    # https://github.com/benoitc/gunicorn/pull/2539
    sys.modules["pkg_resources"] = object()  # type: ignore[assignment]
    import httpx

    del sys.modules["pkg_resources"]

from openai.api_resources import (
    Audio,
    ChatCompletion,
    Completion,
    Customer,
    Deployment,
    Edit,
    Embedding,
    Engine,
    ErrorObject,
    File,
    FineTune,
    FineTuningJob,
    Image,
    Model,
    Moderation,
)
from openai.error import APIError, InvalidRequestError, OpenAIError
from openai.version import VERSION
from openai.api_requestor import init_session
from openai.httpx_utils import (
    setup_custom_sync_session,
    setup_custom_async_session,
    force_init_pulls,
    force_init_sync_pulls,
    force_init_async_pulls,
    reset_sessions,
)

if TYPE_CHECKING:
    import httpx

api_key = os.environ.get("OPENAI_API_KEY")
# Path of a file with an API key, whose contents can change. Supercedes
# `api_key` if set.  The main use case is volume-mounted Kubernetes secrets,
# which are updated automatically.
api_key_path: Optional[str] = os.environ.get("OPENAI_API_KEY_PATH")

organization = os.environ.get("OPENAI_ORGANIZATION")
api_base = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
api_type = os.environ.get("OPENAI_API_TYPE", "open_ai")
api_version = os.environ.get(
    "OPENAI_API_VERSION",
    ("2023-05-15" if api_type in ("azure", "azure_ad", "azuread") else None),
)
verify_ssl_certs = True  # No effect. Certificates are always verified.
proxy = None
app_info = None
enable_telemetry = False  # Ignored; the telemetry feature was removed.
ca_bundle_path = None  # No longer used, feature was removed
debug = False
log = None  # Set to either 'debug' or 'info', controls console logging

sync_session: httpx.Client = init_session(sync=True)
async_session: httpx.AsyncClient = init_session(sync=False)

__version__ = VERSION
__all__ = [
    "APIError",
    "Audio",
    "ChatCompletion",
    "Completion",
    "Customer",
    "Edit",
    "Image",
    "Deployment",
    "Embedding",
    "Engine",
    "ErrorObject",
    "File",
    "FineTune",
    "FineTuningJob",
    "InvalidRequestError",
    "Model",
    "Moderation",
    "OpenAIError",
    "api_base",
    "api_key",
    "api_type",
    "api_key_path",
    "api_version",
    "app_info",
    "ca_bundle_path",
    "debug",
    "enable_telemetry",
    "log",
    "organization",
    "proxy",
    "verify_ssl_certs",
    "sync_session",
    "async_session",
    "setup_custom_sync_session",
    "setup_custom_async_session",
    "force_init_pulls",
    "force_init_sync_pulls",
    "force_init_async_pulls",
    "reset_sessions",
]
