"""
Payload Encoder - Educational Encoding Demonstrations

Encodings:
- URL
- Base64
- Hex (representation only)
"""

import base64
import urllib.parse


class PayloadEncoder:
    def encode(self, payload: str, encoding_type: str) -> str:
        payload = "" if payload is None else str(payload)

        if encoding_type == "url":
            return urllib.parse.quote(payload, safe="")
        if encoding_type == "base64":
            return base64.b64encode(payload.encode("utf-8")).decode("ascii")
        if encoding_type == "hex":
            return payload.encode("utf-8").hex()
        if encoding_type == "none":
            return payload

        raise ValueError(f"Unknown encoding type: {encoding_type}")
