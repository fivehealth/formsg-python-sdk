import json
from time import time
from typing import Any
from typing import ClassVar
from typing import Mapping
from unittest import TestCase
from unittest import skip
from unittest.mock import patch

from formsg import decrypt_content
from formsg import verify_signature
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.exceptions import CryptoError
from nacl.public import Box
from nacl.public import PrivateKey
from nacl.signing import VerifyKey


class WidgetTestCase(TestCase):
    # Obtained from an existing submission
    signature_header: ClassVar[str] = (
        't=1686634361861,'
        's=6487ff798852f40011c89db5,'
        'f=5f166e76a919ad0011b9c43b,'
        'v1=0vQ6O2+Gr7tNOAahSRA1wDceXb6dYxcznVgpDqN5qJNQ3TmIaJqK+FVa/AOA1Q93OVjveZpMYnMuSEtBvIYzAg=='  # noqa
    )

    webhook_uri: ClassVar[str] = 'https://hippocrates.staging.botmd.io/onform/webhook/RvmHghr3CidobY82OBFuGIfRI72kzLED'  # noqa

    # https://github.com/opengovsg/formsg-javascript-sdk#end-to-end-encryption
    request_body: ClassVar[Mapping[str, Any]] = {
        'formId': 'deadbeefdeadbeefdeadbeef',
        'submissionId': 'b0bacafeb0bacafeb0bacafe',
        'created': '1686634361861',
        'attachmentDownloadUrls': {},
    }

    def test_verify_signature_valid(self) -> None:
        with patch('formsg.utils.time', return_value=1686634362):
            self.assertEqual(
                verify_signature(self.webhook_uri, self.signature_header),
                {
                    'f': '5f166e76a919ad0011b9c43b',
                    's': '6487ff798852f40011c89db5',
                    't': '1686634361861',
                    'v1': '0vQ6O2+Gr7tNOAahSRA1wDceXb6dYxcznVgpDqN5qJNQ3TmIaJqK+FVa/AOA1Q93OVjveZpMYnMuSEtBvIYzAg==',  # noqa
                },
            )

    def test_verify_signature_webhook_public_key(self) -> None:
        # Corresponding SIGNING_SECRET_KEY = 'HDBXpu+2/gu10bLHpy8HjpN89xbA6boH9GwibPGJA8BOXmB+zOUpxCP33/S5p8vBWlPokC7gLR0ca8urVwfMUQ=='  # noqa
        with patch('formsg.utils.time', return_value=1686825201):
            self.assertEqual(
                # Obtained from an existing submission
                verify_signature(
                    self.webhook_uri,
                    't=1686825200990,s=648ae8f043bcad001da07464,f=6487b3c9192c47001da9c15c,v1=MZIlOl4sI00eL9hUqNJQJSxHMQ+K4bTZmqVroWfPuk91wn7fjOJrsXJ9fE0NmP/0nBmxGrzKtjCFOx/bH63LCw==',  # noqa
                    webhook_public_key=VerifyKey('Tl5gfszlKcQj99/0uafLwVpT6JAu4C0dHGvLq1cHzFE='.encode('ascii'), encoder=Base64Encoder)  # noqa
                ),
                {
                    'f': '6487b3c9192c47001da9c15c',
                    's': '648ae8f043bcad001da07464',
                    't': '1686825200990',
                    'v1': 'MZIlOl4sI00eL9hUqNJQJSxHMQ+K4bTZmqVroWfPuk91wn7fjOJrsXJ9fE0NmP/0nBmxGrzKtjCFOx/bH63LCw==',  # noqa
                },
            )

    def test_verify_signature_signature_expiry_seconds(self) -> None:
        verify_signature(
            self.webhook_uri,
            self.signature_header,
            signature_expiry_seconds=time() - 1686634361 + 5,
        )

    def test_verify_signature_expired(self) -> None:
        self.assertRaisesRegex(
            BadSignatureError,
            'FormSG signature has expired.',
            verify_signature,
            self.webhook_uri,
            self.signature_header,
        )

    def test_verify_signature_invalid(self) -> None:
        self.assertRaisesRegex(
            BadSignatureError,
            'Signature was forged or corrupt',
            verify_signature,
            'https://example.com/webhook',
            self.signature_header,
        )

    def test_decrypt_content_success(self) -> None:
        pk = PrivateKey.generate()
        secret_key = pk.encode(Base64Encoder).decode('ascii')
        body = {
            **self.request_body,
            'encryptedContent': self._encrypt_content(
                json.dumps({'key': 'hello world'}),
                secret_key,
            ),
        }

        self.assertEqual(
            decrypt_content(body, secret_key),
            {'key': 'hello world'},
        )

    def test_decrypt_content_failure(self) -> None:
        pk = PrivateKey.generate()
        secret_key = pk.encode(Base64Encoder).decode('ascii')
        body = {
            **self.request_body,
            'encryptedContent': self._encrypt_content(
                json.dumps({'key': 'hello world'}),
                secret_key,
            ),
        }

        pk = PrivateKey.generate()
        wrong_secret_key = pk.encode(Base64Encoder).decode('ascii')

        self.assertRaisesRegex(
            CryptoError,
            'An error occurred trying to decrypt the message',
            decrypt_content,
            body, wrong_secret_key,
        )

    @skip('To be implemented')
    def test_decrypt_attachment_success(self) -> None:
        raise NotImplementedError()

    @skip('To be implemented')
    def test_decrypt_attachment_failure(self) -> None:
        raise NotImplementedError()

    def _encrypt_content(self, plaintext: str, secret_key: str) -> str:
        pkey = PrivateKey(secret_key.encode('ascii'), encoder=Base64Encoder)
        formsg_pkey = PrivateKey.generate()  # create a pseudo one

        box = Box(pkey, formsg_pkey.public_key)
        encrypted = box.encrypt(
            plaintext.encode('ascii'), encoder=Base64Encoder,
        )
        nonce = encrypted.nonce.decode('ascii')
        ciphertext = encrypted.ciphertext.decode('ascii')
        public_key = formsg_pkey.public_key.encode(Base64Encoder).decode('ascii')  # noqa

        return f'{public_key};{nonce}:{ciphertext}'
