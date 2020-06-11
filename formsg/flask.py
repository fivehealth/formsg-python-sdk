__all__ = ['decrypt_flask_request']
from .webhook import decrypt_content
from .webhook import verify_signature


def decrypt_flask_request(request, secret_key, webhook_uri=None, signature_expiry_seconds=60):
    if webhook_uri is None:
        webhook_uri = request.url

    verify_signature(webhook_uri, request.headers['X-FormSG-Signature'], signature_expiry_seconds=signature_expiry_seconds)

    body_json = request.get_json()

    return decrypt_content(body_json, secret_key)
#end def
