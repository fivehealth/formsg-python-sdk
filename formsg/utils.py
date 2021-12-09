__all__ = ['verify_signature', 'decrypt_content', 'decrypt_attachment']
import json
import logging
import re
from time import time
from typing import Any
from typing import Dict
from typing import Mapping
from urllib.parse import urlparse

import requests
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box
from nacl.public import PrivateKey
from nacl.public import PublicKey
from nacl.signing import VerifyKey

logger = logging.getLogger(__name__)

formsg_webhook_public_key = VerifyKey('3Tt8VduXsjjd4IrpdCd7BAkdZl/vUCstu9UvTX84FWw=', encoder=Base64Encoder)  # https://github.com/opengovsg/formsg-javascript-sdk#step-3---verify-the-signature
encrypted_content_regex = re.compile(r'^(?P<submission_public_key>[\w\+\/\=]*)\;(?P<nonce>[\w\+\/\=]*)\:(?P<encrypted_message>[\w\+\/\=]*)$')


def verify_signature(webhook_uri: str, signature_header: str, signature_expiry_seconds: float = 60) -> Mapping[str, Any]:
    # v1 is signature, s is submissionId, f is formId, t is submission epoch
    logger.debug(f'X-FormSG-Signature is <{signature_header}>.')

    formsg_signature: Dict[str, Any] = {}
    for part in signature_header.split(','):
        k, v = part.split('=', 1)
        formsg_signature[k] = v
    #end for

    formsg_signature['t'] = int(formsg_signature['t'])

    # Javascript url.href adds a trailing `/` to root domain urls
    # https://github.com/opengovsg/formsg-javascript-sdk/blob/master/src/webhooks.ts#L25
    u = urlparse(webhook_uri)
    if not u.path:
        u = u._replace(path='/')
    webhook_uri = u.geturl()

    formsg_webhook_public_key.verify(
        smessage=f'{webhook_uri}.{formsg_signature["s"]}.{formsg_signature["f"]}.{formsg_signature["t"]}'.encode('ascii'),
        signature=Base64Encoder.decode(formsg_signature['v1']),
    )

    if time() - (formsg_signature['t'] / 1000) > signature_expiry_seconds:
        raise BadSignatureError('FormSG signature has expired.')

    return formsg_signature
#end def


def decrypt_content(
    body: Mapping[str, Any],
    secret_key: str,  # Base64 encoded secret key
) -> Mapping[str, Any]:
    body = body.get('data', body)  # Some FormSG submissions are in a data field while others are not.
    encrypted_content = body['encryptedContent']

    m = encrypted_content_regex.match(encrypted_content)
    assert m, 'Encrypted content has bad format.'
    submission_public_key, nonce, encrypted_message = m.groups()

    box = Box(
        PrivateKey(secret_key, encoder=Base64Encoder),
        PublicKey(submission_public_key, encoder=Base64Encoder),
    )

    plaintext = box.decrypt(encrypted_message, Base64Encoder.decode(nonce), encoder=Base64Encoder)

    return json.loads(plaintext)
#end def


def decrypt_attachment(
    body: Mapping[str, Any],
    field_id: str,
    secret_key: str,  # Base64 encoded secret key
) -> bytes:
    body = body.get('data', body)  # Some FormSG submissions are in a data field while others are not.
    url = body['attachmentDownloadUrls'][field_id]
    r = requests.get(url)
    r.raise_for_status()

    attachment_body = r.json()
    encrypted_file: Mapping[str, str] = attachment_body['encryptedFile']
    box = Box(
        PrivateKey(secret_key, encoder=Base64Encoder),
        PublicKey(encrypted_file['submissionPublicKey'], encoder=Base64Encoder),
    )

    return box.decrypt(encrypted_file['binary'], Base64Encoder.decode(encrypted_file['nonce']), encoder=Base64Encoder)
#end def
