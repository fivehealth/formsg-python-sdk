__all__ = ['decrypt_flask_request']
from typing import Any
from typing import Mapping
from typing import Optional

from .utils import decrypt_content
from .utils import verify_signature


def decrypt_flask_request(request: Any, secret_key: str, webhook_uri: Optional[str] = None, signature_expiry_seconds: float = 60):
    if webhook_uri is None:
        webhook_uri = request.url

    verify_signature(webhook_uri, request.headers['X-FormSG-Signature'], signature_expiry_seconds=signature_expiry_seconds)

    body_json: Mapping[str, Any] = request.get_json()

    return decrypt_content(body_json, secret_key)
#end def
