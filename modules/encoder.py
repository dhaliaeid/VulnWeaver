import base64
import urllib.parse


class PayloadEncoder:
    """Encode payloads using various schemes (educational demonstrations)."""

    def encode(self, payload: str, encoding_type: str) -> str:
        if encoding_type == "url":
            return self.url_encode(payload)
        if encoding_type == "base64":
            return self.base64_encode(payload)
        if encoding_type == "hex":
            return self.hex_encode(payload)
        if encoding_type == "none":
            return payload
        raise ValueError(f"Unknown encoding type: {encoding_type}")

    def url_encode(self, payload: str) -> str:
        # Encode everything (including /) for consistent demonstrations
        return urllib.parse.quote(payload, safe="")

    def base64_encode(self, payload: str) -> str:
        return base64.b64encode(payload.encode("utf-8")).decode("ascii")

    def hex_encode(self, payload: str) -> str:
        # Representation only (no execution context implied)
        return payload.encode("utf-8").hex()

    def html_entity_encode(self, payload: str) -> str:
        return "".join([f"&#{ord(c)};" for c in payload])

    def unicode_encode(self, payload: str) -> str:
        return "".join([f"\\u{ord(c):04x}" for c in payload])

    def double_encode(self, payload: str) -> str:
        return self.url_encode(self.url_encode(payload))
