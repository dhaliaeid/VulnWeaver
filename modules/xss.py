"""
XSS Payload Module - NON-EXECUTING Educational Template Generator

Reference: PortSwigger XSS Cheat Sheet
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

GOAL:
- Teach XSS concepts (Reflected / Stored / DOM)
- Teach context awareness (HTML / Attribute / JavaScript)
- Teach bypass logic concepts (Encoding / Case manipulation / Tag & context switching)
- WITHOUT providing ready-to-run payload strings.

TEMPLATE NOTATION (ALL PLACEHOLDERS):
  [[USER_INPUT]]          - untrusted data reflected/stored/processed
  [[JS_EXPRESSION]]       - example JS expression placeholder (non-executing)
  [[HTML_TAG]]            - placeholder tag name (not an actual tag)
  [[EVENT_ATTR]]          - placeholder for an event handler attribute (on*)
  [[ATTR_NAME]]           - placeholder attribute name
  [[ATTR_VALUE]]          - placeholder attribute value
  [[URL_SCHEME]]          - placeholder for a scheme (http/https/javascript/data)
  [[ENCODED(...)]]        - indicates an encoding demonstration (representation only)
  [[CLOSE_CONTEXT:...]]   - indicates context break-out conceptually (no real delimiters)
  [[SINK:...]]            - DOM sink placeholder (innerHTML, document.write, eval, etc.)

Each entry is clearly labeled:
  is_template: True
  labels: ["TEMPLATE_ONLY", "NON_EXECUTING", "EDUCATIONAL"]

IMPORTANT:
- These are NOT operational payloads.
- They are tokenized patterns intended for learning and documentation.
"""


class XSSPayloadGenerator:
    """Generate non-executing educational XSS payload templates (tokenized patterns)."""

    TEMPLATE_PREFIX = "[[TEMPLATE_ONLY]]"

    def generate_all_contexts(self):
        items = []
        items.extend(self._html_context())
        items.extend(self._attribute_context())
        items.extend(self._javascript_context())
        items.extend(self._dom_based())
        items.extend(self._bypass_concepts())
        return items

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _item(self, *, subtype, context, title, template, description,
              bypass_explanation=None, defensive_notes=None, template_note=None):
        return {
            "type": "XSS",
            "subtype": subtype,
            "context": context,
            "title": title,
            "template": f"{self.TEMPLATE_PREFIX}\n{template}".rstrip(),
            "description": description,
            "template_note": template_note or "",
            "bypass_explanation": bypass_explanation or "",
            "defensive_notes": defensive_notes or "",
            "is_template": True,
            "labels": ["TEMPLATE_ONLY", "NON_EXECUTING", "EDUCATIONAL"],
        }

    # ------------------------------------------------------------------ #
    # HTML CONTEXT
    # ------------------------------------------------------------------ #
    def _html_context(self):
        return [
            self._item(
                subtype="Reflected",
                context="html",
                title="Reflected XSS concept in HTML body",
                template=(
                    "Injection position: <div>[[USER_INPUT]]</div>\n"
                    "Attacker goal (concept): alter HTML structure if output encoding is missing.\n"
                    "Example shape (tokenized): <[[HTML_TAG]] [[ATTR_NAME]]=\"[[ATTR_VALUE]]\">"
                ),
                description=(
                    "Demonstrates reflected XSS when untrusted input is inserted into HTML body context. "
                    "This is tokenized and does not include runnable tags/events."
                ),
                bypass_explanation="If defenses only block specific tag names, attackers may switch to alternative tags/attributes.",
                defensive_notes="Use HTML-context output encoding; avoid inserting raw user data into HTML. CSP helps as defense-in-depth.",
            ),
            self._item(
                subtype="Stored",
                context="html",
                title="Stored XSS lifecycle (store → render)",
                template=(
                    "Storage flow: [[USER_INPUT]] → DB field [[STORAGE_FIELD]] → later rendered:\n"
                    "<div class=\"comment\">[[STORED_INPUT]]</div>\n"
                    "Attacker goal (concept): persisted data reaches a dangerous rendering context."
                ),
                description="Demonstrates stored XSS concept and why persistence increases impact.",
                bypass_explanation="Stored payloads execute for many users; filter bypasses compound over time if sanitization is inconsistent.",
                defensive_notes="Encode on output per context; sanitize rich text with a vetted HTML sanitizer; keep error pages generic.",
            ),
        ]

    # ------------------------------------------------------------------ #
    # ATTRIBUTE CONTEXT
    # ------------------------------------------------------------------ #
    def _attribute_context(self):
        return [
            self._item(
                subtype="Reflected",
                context="attribute",
                title="Attribute context breakout concept (quoted attribute)",
                template=(
                    "Injection position: <a href=\"[[USER_INPUT]]\">Link</a>\n"
                    "Attacker goal (concept): break out of quotes and add a new attribute.\n"
                    "Tokenized breakout pattern:\n"
                    "\" [[EVENT_ATTR]]=\"[[JS_EXPRESSION]]\" [[ATTR_NAME]]=\"[[ATTR_VALUE]]\""
                ),
                description=(
                    "Shows how quote handling matters in attribute context. Uses placeholders instead of real event handlers."
                ),
                bypass_explanation="If a filter only escapes < and > but not quotes, attackers can pivot into attribute injection.",
                defensive_notes="Attribute-context encoding must escape quotes. Prefer safe templating frameworks with auto-escaping.",
            ),
            self._item(
                subtype="Reflected",
                context="attribute",
                title="URL attribute scheme validation concept",
                template=(
                    "Injection position: href=\"[[USER_INPUT]]\" or src=\"[[USER_INPUT]]\"\n"
                    "Risk concept: unsafe schemes.\n"
                    "Tokenized scheme placeholder:\n"
                    "[[URL_SCHEME]]:[[JS_EXPRESSION]]\n"
                    "Encoding demo (representation only): [[ENCODED(URL_SCHEME)]]:[[JS_EXPRESSION]]"
                ),
                description=(
                    "Demonstrates that URL attributes must validate schemes. Does not include a real scheme string."
                ),
                bypass_explanation="Naive filters that search for raw strings can miss encoded representations if decoding occurs later.",
                defensive_notes="Whitelist allowed schemes (http/https). Apply validation after normalization/decoding (once).",
            ),
            self._item(
                subtype="Reflected",
                context="attribute",
                title="Unquoted attribute value risk concept",
                template=(
                    "Injection position: <input value=[[USER_INPUT]]>\n"
                    "Concept: whitespace terminates unquoted value; attacker can append attributes.\n"
                    "Tokenized pattern:\n"
                    "[[ATTR_VALUE]] [[EVENT_ATTR]]=[[JS_EXPRESSION]]"
                ),
                description="Shows why unquoted attributes widen the attack surface.",
                bypass_explanation="No quote escaping needed; delimiter handling becomes the weak point.",
                defensive_notes="Always quote attribute values and apply attribute-context encoding.",
            ),
        ]

    # ------------------------------------------------------------------ #
    # JAVASCRIPT CONTEXT
    # ------------------------------------------------------------------ #
    def _javascript_context(self):
        return [
            self._item(
                subtype="Reflected",
                context="javascript",
                title="JS string literal breakout concept",
                template=(
                    "Injection position: const q = \"[[USER_INPUT]]\";\n"
                    "Attacker goal (concept): terminate string and alter control flow.\n"
                    "Tokenized pattern:\n"
                    "[[STRING_BREAK]] ; [[JS_EXPRESSION]] ; [[COMMENT_REST]]"
                ),
                description="Demonstrates JavaScript-context escaping requirements using placeholders.",
                bypass_explanation="If only HTML encoding is applied, JS context remains vulnerable.",
                defensive_notes="Use safe data embedding (JSON serialization) and avoid building JS code via concatenation.",
            ),
            self._item(
                subtype="Reflected",
                context="javascript",
                title="Script-context boundary concept (HTML tokenizer vs JS parser)",
                template=(
                    "Concept: browser HTML tokenization can treat script boundaries specially.\n"
                    "Tokenized representation:\n"
                    "[[CLOSE_CONTEXT:SCRIPT_TAG]] [[OPEN_CONTEXT:SCRIPT_TAG]] [[JS_EXPRESSION]]"
                ),
                description=(
                    "Explains the special handling of script boundaries without providing real closing/opening sequences."
                ),
                bypass_explanation="Tokenization happens before JS parsing; defenses must treat script context as high risk.",
                defensive_notes="Avoid reflecting untrusted data inside <script>. If unavoidable, escape sequences appropriately and prefer JSON-in-data-attributes.",
            ),
            self._item(
                subtype="Reflected",
                context="javascript",
                title="Template literal delimiter concept",
                template=(
                    "Injection position: const x = `Hello [[USER_INPUT]]`;\n"
                    "Concept: different delimiter (backtick) and interpolation.\n"
                    "Tokenized pattern:\n"
                    "[[TEMPLATE_LITERAL_BREAK]] [[JS_EXPRESSION]] [[TEMPLATE_LITERAL_RESUME]]"
                ),
                description="Demonstrates that encoders must handle all JS string forms (single/double/backtick).",
                bypass_explanation="Encoders that only handle ' and \" may miss other JS delimiters and interpolation patterns.",
                defensive_notes="Avoid inline JS data; use JSON + DOM reads. Encode per JS context if you must embed.",
            ),
        ]

    # ------------------------------------------------------------------ #
    # DOM-BASED XSS
    # ------------------------------------------------------------------ #
    def _dom_based(self):
        return [
            self._item(
                subtype="DOM-based",
                context="dom",
                title="DOM XSS data flow (source → sink) template",
                template=(
                    "Client-side data flow:\n"
                    "  Source: [[SOURCE]] (e.g., location.search/hash - placeholder)\n"
                    "  Transform: [[TRANSFORM]] (decode/parse - placeholder)\n"
                    "  Sink: [[SINK:innerHTML/document.write]]\n"
                    "Attacker goal (concept): untrusted data reaches a dangerous sink."
                ),
                description="Shows DOM XSS as a client-side flow where server WAF may not help.",
                bypass_explanation="If the source is fragment (#), it never reaches the server; only browser-side controls can mitigate.",
                defensive_notes="Prefer textContent; sanitize before HTML insertion; consider Trusted Types where available.",
            ),
            self._item(
                subtype="DOM-based",
                context="dom",
                title="Direct code-eval sink concept (description-only)",
                template=(
                    "Dangerous sink concept:\n"
                    "  [[SINK:eval/Function/setTimeout(string)]]( [[USER_INPUT]] )\n"
                    "This is a conceptual pattern only — do not execute."
                ),
                description="Highlights the highest-risk DOM sinks without providing executable code strings.",
                bypass_explanation="HTML filtering is irrelevant when user input is evaluated as code.",
                defensive_notes="Never use eval-family with user input. Use function references and strict input validation for logic decisions.",
            ),
        ]

    # ------------------------------------------------------------------ #
    # BYPASS CONCEPTS (NO OPERATIONAL STRINGS)
    # ------------------------------------------------------------------ #
    def _bypass_concepts(self):
        return [
            self._item(
                subtype="Bypass",
                context="bypass",
                title="Encoding bypass concept (representation-only)",
                template=(
                    "Concept: Normalization/decoding order matters.\n"
                    "Tokenized forms:\n"
                    "  Raw:      [[USER_INPUT]]\n"
                    "  URL-enc:   [[ENCODED_URL(USER_INPUT)]]\n"
                    "  Double:    [[ENCODED_URL(ENCODED_URL(USER_INPUT))]]\n"
                    "  HTML-ent:  [[ENCODED_HTML_ENTITY(USER_INPUT)]]\n"
                    "Key point: filters must normalize/fully decode once before validation."
                ),
                description="Demonstrates encoding-based bypass logic without providing real encoded attack strings.",
                bypass_explanation="If input is decoded multiple times or filtered before decoding, filters can miss dangerous characters.",
                defensive_notes="Decode/normalize exactly once before validation; apply context-aware output encoding after validation.",
            ),
            self._item(
                subtype="Bypass",
                context="bypass",
                title="Case manipulation bypass concept",
                template=(
                    "Concept: some parsers are case-insensitive while filters are case-sensitive.\n"
                    "Tokenized example:\n"
                    "  <[[MIXED_CASE_TOKEN]]> ... </[[MIXED_CASE_TOKEN]]>"
                ),
                description="Shows why naive case-sensitive denylist checks fail.",
                bypass_explanation="Normalizing to lowercase defeats this class of bypass, but denylist filtering remains fragile.",
                defensive_notes="Prefer allowlists + real HTML parsing/sanitization. Avoid regex-based HTML security.",
            ),
            self._item(
                subtype="Bypass",
                context="bypass",
                title="Tag/context switching concept",
                template=(
                    "Concept: if one tag/keyword is blocked, attackers may switch context.\n"
                    "Tokenized alternatives:\n"
                    "  HTML body: <[[HTML_TAG]]>...\n"
                    "  Attribute: [[EVENT_ATTR]]=\"[[JS_EXPRESSION]]\"\n"
                    "  URL attr:  [[URL_SCHEME]]:[[JS_EXPRESSION]]\n"
                    "  DOM sink:  [[SINK:innerHTML]]( [[USER_INPUT]] )"
                ),
                description="Demonstrates context switching as an evasion strategy (conceptual).",
                bypass_explanation="Blocking one vector (e.g., a keyword) doesn’t remove the underlying sink/context vulnerability.",
                defensive_notes="Fix the sink: contextual encoding + safe APIs + sanitization. Don’t rely on keyword blocking.",
            ),
            self._item(
                subtype="Bypass",
                context="bypass",
                title="Polyglot concept (description-only, no string)",
                template=(
                    "Polyglot concept (description-only):\n"
                    "  A structure designed to survive multiple contexts by closing wrappers and landing in a permissive context.\n"
                    "  Represented as: [[CLOSE_CONTEXT:*]] → [[FALLTHROUGH_CONTEXT]] → [[JS_EXPRESSION]]\n"
                    "No concrete polyglot string is provided."
                ),
                description="Keeps the educational concept without including an operational polyglot skeleton.",
                bypass_explanation="Polyglots exploit inconsistent context handling and tokenization boundaries.",
                defensive_notes="Apply strict context-aware encoding and sanitize HTML with a parser-based allowlist; enforce CSP/Trusted Types.",
            ),
        ]
