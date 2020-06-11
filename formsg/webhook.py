__all__ = ['verify_signature', 'decrypt_content']
import json
import logging
import re
from time import time
from urllib.parse import urlparse

from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box
from nacl.public import PrivateKey
from nacl.public import PublicKey
from nacl.signing import VerifyKey

logger = logging.getLogger(__name__)

FORMSG_WEBHOOK_PUBLIC_KEY = VerifyKey('3Tt8VduXsjjd4IrpdCd7BAkdZl/vUCstu9UvTX84FWw=', encoder=Base64Encoder)
ENCRYPTED_CONTENT_REGEX = re.compile(r'^(?P<submission_public_key>[\w\+\/\=]*)\;(?P<nonce>[\w\+\/\=]*)\:(?P<encrypted_message>[\w\+\/\=]*)$')


def verify_signature(webhook_uri, signature_header, signature_expiry_seconds=60):
    # v1 is signature, s is submissionId, f is formId, t is submission epoch
    logger.debug(f'X-FormSG-Signature is <{signature_header}>.')
    formsg_signature = dict(part.split('=', 1) for part in signature_header.split(','))
    formsg_signature['t'] = int(formsg_signature['t'])

    # Javascript url.href adds a trailing `/` to root domain urls
    # https://github.com/opengovsg/formsg-javascript-sdk/blob/master/src/webhooks.ts#L25
    u = urlparse(webhook_uri)
    if not u.path:
        u = u._replace(path='/')
    webhook_uri = u.geturl()

    FORMSG_WEBHOOK_PUBLIC_KEY.verify(
        smessage=f'{webhook_uri}.{formsg_signature["s"]}.{formsg_signature["f"]}.{formsg_signature["t"]}'.encode('ascii'),
        signature=Base64Encoder.decode(formsg_signature['v1']),
    )

    if time() - (formsg_signature['t'] / 1000) > signature_expiry_seconds:
        raise BadSignatureError('FormSG signature has expired.')

    return formsg_signature
#end def


def decrypt_content(body_json, secret_key):
    if 'data' in body_json:
        encrypted_content = body_json['data']['encryptedContent']
    else:
        encrypted_content = body_json['encryptedContent']  # old version POST body
    #end if

    submission_public_key, nonce, encrypted_message = ENCRYPTED_CONTENT_REGEX.match(encrypted_content).groups()

    box = Box(
        PrivateKey(secret_key, encoder=Base64Encoder),
        PublicKey(submission_public_key, encoder=Base64Encoder),
    )

    plaintext = box.decrypt(encrypted_message, Base64Encoder.decode(nonce), encoder=Base64Encoder)

    return json.loads(plaintext)
#end def
