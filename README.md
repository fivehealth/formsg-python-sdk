# FormSG Python SDK

[![PyPI version](https://img.shields.io/pypi/v/formsg.svg)](https://pypi.python.org/pypi/formsg/)
[![PyPI license](https://img.shields.io/pypi/l/formsg.svg)](https://pypi.python.org/pypi/formsg/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/formsg.svg)](https://pypi.python.org/pypi/formsg/)
[![PyPI status](https://img.shields.io/pypi/status/formsg.svg)](https://pypi.python.org/pypi/formsg/)
[![PyPI download total](https://img.shields.io/pypi/dm/formsg.svg)](https://pypi.python.org/pypi/formsg/)

This SDK provides convenient utilities for verifying FormSG webhooks and decrypting submissions in Python and Flask or Django.

## Installation

```bash
pip install formsg
```

## Usage

The SDK provides two main utility functions for handling FormSG webhook:

- [`webhook_uri: str, signature_header: str, signature_expiry_seconds: float = 60)`](formsg/utils.py) verifies that the incoming webhook's signature is valid based on the FormSG production public key.
It raises a `nacl.exceptions.BadSignatureError` if the signature is invalid.
The signature header is usually found in the `X-FormSG-Signature` header.
Details on how the signature is constructed can be found [here](https://github.com/opengovsg/formsg-javascript-sdk/#verifying-signatures-manually).

- [`decrypt_content(body: Mapping[str, Any], secret_key: str)`](formsg/utils.py) will decrypt the encrypted content using the given Base-64 encoded secret key.
`body` is expected to be a dictionary-like object.

- [`decrypt_attachment(body: Mapping[str, Any], field_id: str, secret_key: str)`](formsg/utils.py) will decrypt the encrypted content using the given Base-64 encoded secret key.
`body` is expected to be a dictionary-like object.

For convenience, the SDK implements a [`decrypt_django_request`](formsg/django.py) and [`decrypt_flask_request`](formsg/flask.py) which returns the decrypted FormSG content from a Django/Flask request object directly.

### Example with Flask

```python
from formsg.flask import decrypt_flask_request

from flask import Flask
from flask import jsonify
from flask import request

app = Flask(__name__)


@app.route('/formsg_webhook', methods=['POST'])
def formsg_webhook():
    decrypted = decrypt_flask_request(
        request,
        secret_key='xxx',
        webhook_uri='https://xxx.ngrok.io/formsg_webhook',  # we use ngrok to test our webhooks locally
    )

    return jsonify(decrypted)
#end def


if __name__ == '__main__':
    app.run(debug=True)
#end if
```

## Contributions

If you find any issues or would like to contribute improvements, please feel free to raise them in this repository directly.
