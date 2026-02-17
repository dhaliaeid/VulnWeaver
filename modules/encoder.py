"""
Payload Encoder Module - Educational Encoding Demonstrations

Demonstrates various encoding schemes used in security testing:
- URL encoding
- Base64 encoding
- Hexadecimal encoding
"""

import base64
import urllib.parse


class PayloadEncoder:
    """Encode payloads using various schemes"""
    
    def encode(self, payload, encoding_type):
        """
        Encode payload using specified type
        
        Args:
            payload (str): Original payload string
            encoding_type (str): Type of encoding (url, base64, hex)
            
        Returns:
            str: Encoded payload
        """
        if encoding_type == 'url':
            return self.url_encode(payload)
        elif encoding_type == 'base64':
            return self.base64_encode(payload)
        elif encoding_type == 'hex':
            return self.hex_encode(payload)
        elif encoding_type == 'none':
            return payload
        else:
            raise ValueError(f"Unknown encoding type: {encoding_type}")
    
    def url_encode(self, payload):
        """
        URL encode payload
        
        Explanation: Converts special characters to %XX format.
        Used to bypass filters that don't decode URLs before validation.
        
        Example: <script> becomes %3Cscript%3E
        """
        return urllib.parse.quote(payload)
    
    def url_encode_all(self, payload):
        """
        URL encode all characters including alphanumeric
        
        Explanation: Some WAFs decode URLs but may not handle 
        fully encoded payloads properly.
        """
        return ''.join([f'%{ord(c):02x}' for c in payload])
    
    def base64_encode(self, payload):
        """
        Base64 encode payload
        
        Explanation: Binary-to-text encoding that completely transforms
        the payload. Some applications decode Base64 automatically.
        
        Example: <script> becomes PHNjcmlwdD4=
        """
        payload_bytes = payload.encode('utf-8')
        encoded_bytes = base64.b64encode(payload_bytes)
        return encoded_bytes.decode('utf-8')
    
    def hex_encode(self, payload):
        """
        Hexadecimal encode payload
        
        Explanation: Represents each character as its hex value.
        Used in contexts where hex is interpreted (SQL, JavaScript).
        
        Example: A becomes 0x41
        """
        return '0x' + payload.encode('utf-8').hex()
    
    def html_entity_encode(self, payload):
        """
        HTML entity encode payload
        
        Explanation: Converts characters to HTML entities (&#NN;).
        Browsers decode entities, but filters may not.
        
        Example: < becomes &#60;
        """
        return ''.join([f'&#{ ord(c)};' for c in payload])
    
    def unicode_encode(self, payload):
        r"""
        Unicode encode payload
        
        Explanation: Represents characters as \uXXXX format.
        JavaScript interprets unicode escapes.
        
        Example: A becomes \u0041
        """
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    def double_encode(self, payload):
        """
        Double URL encoding
        
        Explanation: Some systems decode twice. First decode may pass
        validation, but second decode executes malicious payload.
        
        Example: < becomes %253C (% is encoded as %25)
        """
        first_encode = self.url_encode(payload)
        return self.url_encode(first_encode)
    
    @staticmethod
    def demonstrate_encodings(sample_payload="<script>alert('XSS')</script>"):
        """
        Demonstrate all encoding types on a sample payload
        
        Returns detailed explanation of each encoding
        """
        encoder = PayloadEncoder()
        
        demonstrations = {
            'Original': sample_payload,
            'URL Encoded': encoder.url_encode(sample_payload),
            'Base64': encoder.base64_encode(sample_payload),
            'Hex': encoder.hex_encode(sample_payload),
            'HTML Entities': encoder.html_entity_encode(sample_payload),
            'Unicode': encoder.unicode_encode(sample_payload),
            'Double URL': encoder.double_encode(sample_payload)
        }
        
        return demonstrations


class ObfuscationTechniques:
    """Demonstrate obfuscation techniques"""
    
    @staticmethod
    def comment_insertion(payload, comment_type='inline'):
        """
        Insert comments to break signature matching
        
        SQL Example: UN/**/ION SE/**/LECT
        Explanation: Comments are ignored but break string matching
        """
        if comment_type == 'inline':
            # Insert /**/ between words
            words = payload.split()
            return '/**/'.join(words)
        return payload
    
    @staticmethod
    def whitespace_abuse(payload, space_replacement='\t'):
        """
        Replace spaces with tabs, newlines, or other whitespace
        
        Explanation: Parsers treat various whitespace as equivalent,
        but filters may only check for spaces
        """
        return payload.replace(' ', space_replacement)
    
    @staticmethod
    def case_variation(payload):
        """
        Alternate character case
        
        Explanation: HTML/SQL are case-insensitive but filters may not be
        
        Example: <ScRiPt>
        """
        result = []
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)
    
    @staticmethod
    def concatenation(payload, language='sql'):
        """
        Break payload into concatenated parts
        
        SQL: 'UN'+'ION'
        JavaScript: 'aler'+'t'
        """
        if language == 'sql':
            mid = len(payload) // 2
            return f"'{payload[:mid]}'||'{payload[mid:]}'"
        elif language == 'javascript':
            mid = len(payload) // 2
            return f"'{payload[:mid]}'+ '{payload[mid:]}'"
        return payload