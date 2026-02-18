"""
XSS Payload Module - Educational Template Generator

Reference:
PortSwigger XSS Cheat Sheet
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Scope:
- Reflected / Stored / DOM-based concepts
- Context awareness (HTML / Attribute / JavaScript)
- Bypass logic explanation (Encoding / Case manipulation / Context switching)
- Default output: NON-EXECUTING tokenized templates
- Optional lab proof payloads (for DVWA/Juice Shop screenshots) via vw.py --mode lab --i-understand
"""


class XSSPayloadGenerator:
    TEMPLATE_PREFIX = "[[TEMPLATE_ONLY]]"

    def generate_all_contexts(self):
        items = []
        items.extend(self._html_context())
        items.extend(self._attribute_context())
        items.extend(self._javascript_context())
        items.extend(self._dom_context())
        items.extend(self._bypass_concepts())
        return items

    def _item(self, subtype, context, title, template, description, bypass_explanation="", defensive_notes="", lab_payload=""):
        clean = template.strip("\n")
        return {
            "type": "XSS",
            "subtype": subtype,
            "context": context,
            "title": title,
            "template": f"{self.TEMPLATE_PREFIX}\n{clean}",
            "payload": "",  # template-only by default
            "description": description,
            "bypass_explanation": bypass_explanation,
            "defensive_notes": defensive_notes,
            "is_template": True,
            "labels": ["TEMPLATE_ONLY", "NON_EXECUTING", "EDUCATIONAL"],
            # Used ONLY when user enables lab mode explicitly:
            "lab_payload": lab_payload,
        }

    # ----------------------------
    # HTML context
    # ----------------------------
    def _html_context(self):
        return [
            self._item(
                "Reflected",
                "HTML",
                "HTML body injection concept",
                """
Injection point:
  <div>[[USER_INPUT]]</div>

Concept:
  Untrusted input is reflected inside HTML body without context-aware encoding.

Tokenized pattern (non-operational):
  <[[HTML_TAG]] [[ATTR_NAME]]="[[ATTR_VALUE]]">
""",
                "Demonstrates reflected XSS risk in HTML context.",
                "If defenses block only one tag name, attackers may switch to another tag/attribute.",
                "Use HTML output encoding by context; apply CSP as defense-in-depth.",
                lab_payload="<script>alert(1)</script>",
            ),
            self._item(
                "Stored",
                "HTML",
                "Stored XSS lifecycle concept",
                """
Data flow:
  [[USER_INPUT]] -> database -> rendered later for other users

Render position example:
  <div class="comment">[[STORED_INPUT]]</div>
""",
                "Demonstrates stored XSS concept where payload persists.",
                "Stored input increases impact: it triggers for many users, not only the victim who submitted it.",
                "Encode on output; sanitize rich text using a vetted HTML sanitizer.",
                lab_payload="<img src=x onerror=alert(1)>",
            ),
        ]

    # ----------------------------
    # Attribute context
    # ----------------------------
    def _attribute_context(self):
        return [
            self._item(
                "Reflected",
                "Attribute",
                "Quoted attribute breakout concept",
                """
Injection position:
  <a href="[[USER_INPUT]]">Link</a>

Concept:
  If quotes aren't encoded, attacker may break out and add a new attribute.

Tokenized breakout (non-operational):
  " [[EVENT_ATTR]]="[[JS_EXPRESSION]]"
""",
                "Shows why attribute-context encoding must escape quotes.",
                "Escaping < and > is insufficient if quotes are not encoded.",
                "Apply attribute-context encoding; always quote attribute values.",
                lab_payload='"><svg onload=alert(1)>',
            ),
            self._item(
                "Reflected",
                "Attribute",
                "Unsafe URL scheme concept",
                """
Injection position:
  href="[[USER_INPUT]]" or src="[[USER_INPUT]]"

Concept:
  [[URL_SCHEME]]:[[JS_EXPRESSION]]

Encoding representation:
  [[ENCODED(URL_SCHEME)]]:[[JS_EXPRESSION]]
""",
                "Demonstrates the risk of unsafe URL schemes and encoding/normalization order.",
                "If validation occurs before decoding/normalization, encoded values may bypass checks.",
                "Whitelist allowed schemes (http/https). Validate after normalization (decode once).",
                lab_payload="javascript:alert(1)",
            ),
        ]

    # ----------------------------
    # JavaScript context
    # ----------------------------
    def _javascript_context(self):
        return [
            self._item(
                "Reflected",
                "JavaScript",
                "JavaScript string breakout concept",
                """
Injection position:
  const q = "[[USER_INPUT]]";

Conceptual pattern:
  [[STRING_BREAK]];
  [[JS_EXPRESSION]];
  [[COMMENT_REST]];
""",
                "Demonstrates why JS-context encoding is different from HTML encoding.",
                "HTML encoding alone does not secure JavaScript contexts.",
                "Prefer JSON serialization and avoid string concatenation into JS code.",
                lab_payload='";alert(1);//',
            ),
        ]

    # ----------------------------
    # DOM-based
    # ----------------------------
    def _dom_context(self):
        return [
            self._item(
                "DOM-based",
                "DOM",
                "Client-side source-to-sink flow",
                """
Source:
  [[SOURCE]] (e.g., location.search / location.hash)

Sink:
  [[SINK:innerHTML / document.write]]

Concept:
  Untrusted client-side data reaches a dangerous sink.
""",
                "Demonstrates DOM XSS concept (client-side).",
                "URL fragments (#) never reach the server; server-side WAF can't see them.",
                "Use textContent; sanitize before HTML insertion; consider Trusted Types.",
                lab_payload="#<img src=x onerror=alert(1)>",
            ),
        ]

    # ----------------------------
    # Bypass concepts
    # ----------------------------
    def _bypass_concepts(self):
        return [
            self._item(
                "Bypass",
                "Encoding",
                "Encoding normalization concept",
                """
Raw input:
  [[USER_INPUT]]

URL encoded:
  [[ENCODED_URL(USER_INPUT)]]

Double encoded:
  [[ENCODED_URL(ENCODED_URL(USER_INPUT))]]
""",
                "Explains encoding-based bypass logic (conceptual).",
                "Filtering before decoding can miss dangerous characters.",
                "Normalize/decode exactly once before validation; encode on output by context.",
            ),
            self._item(
                "Bypass",
                "Case manipulation",
                "Case sensitivity bypass concept",
                """
Concept:
  <[[MIXED_CASE_TOKEN]]> ... </[[MIXED_CASE_TOKEN]]>

Why it matters:
  Some parsers are case-insensitive while filters are case-sensitive.
""",
                "Shows why naive case-sensitive denylist checks fail.",
                "Normalizing to lowercase defeats this specific bypass, but denylist filtering remains fragile.",
                "Prefer allowlists + parser-based sanitization; avoid regex-based HTML security.",
            ),
            self._item(
                "Bypass",
                "Context switching",
                "Tag/context switching concept",
                """
Alternative contexts attackers may pivot to:
  HTML:       <[[HTML_TAG]]>
  Attribute:  [[EVENT_ATTR]]="[[JS_EXPRESSION]]"
  URL:        [[URL_SCHEME]]:[[JS_EXPRESSION]]
  DOM sink:   [[SINK:innerHTML]]([[USER_INPUT]])
""",
                "Demonstrates how attackers pivot across contexts when one vector is blocked.",
                "Blocking one keyword does not remove the vulnerable sink/context.",
                "Fix the sink with context-aware encoding + safe APIs; do not rely on keyword blocking.",
            ),
        ]
