__all__ = ['verify_signature', 'decrypt_content', 'decrypt_attachment']
import json
import logging
import re
from time import time
from typing import Any
from typing import Dict
from typing import Mapping
from typing import Optional
from typing import cast
from urllib.parse import urlparse

from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box
from nacl.public import PrivateKey
from nacl.public import PublicKey
from nacl.signing import VerifyKey
import requests

logger = logging.getLogger(__name__)

# See https://github.com/opengovsg/formsg-javascript-sdk#step-3---verify-the-signature  # noqa
formsg_webhook_public_key = VerifyKey(
    b'3Tt8VduXsjjd4IrpdCd7BAkdZl/vUCstu9UvTX84FWw=',
    encoder=Base64Encoder,
)
encrypted_content_regex = re.compile((
    r'^(?P<submission_public_key>[\w\+\/\=]*)\;'
    r'(?P<nonce>[\w\+\/\=]*)\:'
    r'(?P<encrypted_message>[\w\+\/\=]*)$'
))


def verify_signature(
    webhook_uri: str,
    signature_header: str,
    signature_expiry_seconds: float = 60,
    webhook_public_key: VerifyKey = formsg_webhook_public_key,
) -> Mapping[str, Any]:
    # v1 is signature, s is submissionId, f is formId, t is submission epoch
    logger.debug('X-FormSG-Signature is <%s>.', signature_header)

    formsg_signature: Dict[str, Any] = {}
    for part in signature_header.split(','):
        k, v = part.split('=', 1)
        formsg_signature[k] = v

    # Javascript url.href adds a trailing `/` to root domain urls
    # https://github.com/opengovsg/formsg-javascript-sdk/blob/master/src/webhooks.ts#L25
    u = urlparse(webhook_uri)
    if not u.path:
        u = u._replace(path='/')
    webhook_uri = u.geturl()

    signature_timestamp_millis = int(formsg_signature['t'])
    webhook_public_key.verify(
        smessage='.'.join((
            webhook_uri,
            formsg_signature['s'],
            formsg_signature['f'],
            formsg_signature['t'],
        )).encode('ascii'),
        signature=Base64Encoder.decode(formsg_signature['v1']),
    )

    if time() - (signature_timestamp_millis / 1000) > signature_expiry_seconds:
        raise BadSignatureError('FormSG signature has expired.')

    return formsg_signature


def decrypt_content(
    body: Mapping[str, Any],
    secret_key: str,  # Base64 encoded secret key
) -> Mapping[str, Any]:
    # Some FormSG submissions are in a data field while others are not.
    body = body.get('data', body)
    encrypted_content = body['encryptedContent']

    m = encrypted_content_regex.match(encrypted_content)
    if not m:
        raise ValueError('Encrypted content has bad format.')

    submission_public_key = m.group('submission_public_key')
    nonce = m.group('nonce')
    encrypted_message = m.group('encrypted_message')

    box = Box(
        PrivateKey(secret_key.encode('ascii'), encoder=Base64Encoder),
        PublicKey(
            submission_public_key.encode('ascii'),
            encoder=Base64Encoder,
        ),
    )

    plaintext = box.decrypt(
        encrypted_message.encode('ascii'),
        Base64Encoder.decode(nonce.encode('ascii')),
        encoder=Base64Encoder,
    )

    return cast(Mapping[str, Any], json.loads(plaintext))


def decrypt_attachment(
    body: Mapping[str, Any],
    field_id: str,
    secret_key: str,  # Base64 encoded secret key
    timeout: float = 5,  # Default timeout for requests
) -> Optional[bytes]:
    # Some FormSG submissions are in a data field while others are not.
    body = body.get('data', body)

    # DEVX-467: `field_id` did not include an attachment; its an optional field
    try:
        # Either attachmentDownloadUrls or field_id can be missing
        url = body['attachmentDownloadUrls'][field_id]
    except KeyError:
        return None

    r = requests.get(url, timeout=timeout)
    r.raise_for_status()

    attachment_body = r.json()
    encrypted_file: Mapping[str, str] = attachment_body['encryptedFile']
    box = Box(
        PrivateKey(secret_key.encode('ascii'), encoder=Base64Encoder),
        PublicKey(
            encrypted_file['submissionPublicKey'].encode('ascii'),
            encoder=Base64Encoder,
        ),
    )

    return box.decrypt(
        encrypted_file['binary'].encode('ascii'),
        Base64Encoder.decode(encrypted_file['nonce'].encode('ascii')),
        encoder=Base64Encoder,
    )
