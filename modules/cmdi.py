"""
Command Injection Payload Module - Educational Pattern Generator (Pattern-Based)

Reference: OWASP Command Injection
https://owasp.org/www-community/attacks/Command_Injection

Scope compliance:
- Pattern-based templates only (no live execution, no request sending)
- OS-specific logic (Linux vs Windows vs both)
- Command separators are represented as strings
- Commands are DISABLED BY DEFAULT and replaced with placeholders
- Defensive notes explain why filters fail and what to do instead
"""


class CMDIPayloadGenerator:
    """
    Generate educational command injection patterns.
    By default this generator returns NON-EXECUTING templates (placeholders).
    """

    def __init__(self, os_type: str = "linux", enable_commands: bool = False):
        self.os_type = (os_type or "linux").lower()
        if self.os_type not in ("linux", "windows", "both"):
            raise ValueError("os_type must be one of: linux, windows, both")

        # Commands disabled by default
        self.enable_commands = bool(enable_commands)

        self.separators = self._get_separators()

        # Non-executing placeholders (safe by default)
        self.cmd_placeholder = "[[CMD_PLACEHOLDER]]"
        self.info_cmd_placeholder = "[[INFO_CMD_PLACEHOLDER]]"
        self.file_read_placeholder = "[[FILE_READ_CMD_PLACEHOLDER]]"

    # -----------------------------
    # Separator sets (strings only)
    # -----------------------------
    def _get_separators(self):
        if self.os_type == "linux":
            return [";", "|", "||", "&", "&&", "\\n", "`...`", "$( ... )"]
        if self.os_type == "windows":
            return ["&", "|", "||", "&&", "\\n", "^"]
        return [";", "|", "||", "&", "&&", "\\n"]  # both

    # -----------------------------
    # Public API
    # -----------------------------
    def generate_all_patterns(self):
        payloads = []

        if self.os_type in ("linux", "both"):
            payloads.extend(self._linux_patterns())

        if self.os_type in ("windows", "both"):
            payloads.extend(self._windows_patterns())

        payloads.extend(self._bypass_concepts_description_only())
        payloads.append(self._defense_strategy_item())

        return payloads

    # -----------------------------
    # Internal helper
    # -----------------------------
    def _item(self, *, os_name, separator, template, description, bypass_explanation, defensive_notes, note=None, subtype=None):
        d = {
            "type": "Command Injection",
            "subtype": subtype or "Pattern",
            "os": os_name,
            "separator": separator,                 # separator as a STRING (explicit)
            "template": template,                   # template (non-executing by default)
            "description": description,
            "bypass_explanation": bypass_explanation,
            "defensive_notes": defensive_notes,
            "commands_enabled": self.enable_commands,
            "is_template": True,
            "labels": ["TEMPLATE_ONLY", "EDUCATIONAL", "NO_EXECUTION"],
        }
        if note:
            d["note"] = note
        return d

    def _choose_cmd(self, kind: str):
        """
        Return a safe placeholder by default. If enable_commands=True, return a basic example
        command for demonstration. (Still does NOT execute anything; it only generates strings.)
        """
        if not self.enable_commands:
            if kind == "info":
                return self.info_cmd_placeholder
            if kind == "file":
                return self.file_read_placeholder
            return self.cmd_placeholder

        # If explicitly enabled, provide minimal examples (still educational)
        if self.os_type == "windows":
            if kind == "info":
                return "whoami"
            if kind == "file":
                return r"type C:\Windows\System32\drivers\etc\hosts"
            return "whoami"

        # linux / both defaults to linux-like examples
        if kind == "info":
            return "whoami"
        if kind == "file":
            return "cat /etc/hosts"
        return "whoami"

    # -----------------------------
    # Linux patterns (templates)
    # -----------------------------
    def _linux_patterns(self):
        cmd_info = self._choose_cmd("info")
        cmd_file = self._choose_cmd("file")
        cmd_generic = self._choose_cmd("generic")

        return [
            self._item(
                os_name="Linux/Unix",
                separator=";",
                template=f"[[SEP:semicolon]] {cmd_generic}",
                description="Sequential command chaining using semicolon",
                bypass_explanation="`;` starts a new command regardless of previous exit status.",
                defensive_notes="Avoid invoking a shell with user input. Use subprocess with shell=False and strict allowlist validation.",
                note="Commands are placeholders unless explicitly enabled.",
            ),
            self._item(
                os_name="Linux/Unix",
                separator="|",
                template=f"[[SEP:pipe]] {cmd_generic}",
                description="Pipe chaining concept",
                bypass_explanation="`|` pipes stdout of the first command into the next command.",
                defensive_notes="Never concatenate user input into shell pipelines. Prefer native APIs (filesystem/network libs) instead of shell.",
            ),
            self._item(
                os_name="Linux/Unix",
                separator="&&",
                template=f"[[SEP:and]] {cmd_info}",
                description="Conditional execution (only if previous succeeds)",
                bypass_explanation="`&&` executes the next command only if the previous returns exit code 0.",
                defensive_notes="Defense is not 'block &&'. Use safe execution primitives and strict allowlists.",
            ),
            self._item(
                os_name="Linux/Unix",
                separator="||",
                template=f"[[SEP:or]] {cmd_info}",
                description="Conditional execution (only if previous fails)",
                bypass_explanation="`||` executes the next command only if the previous fails (non-zero).",
                defensive_notes="Consistent error handling and no shell usage are key; keyword filtering is unreliable.",
            ),
            self._item(
                os_name="Linux/Unix",
                separator="\\n",
                template=f"[[SEP:newline]] {cmd_info}",
                description="Newline as a command separator (shell/script contexts)",
                bypass_explanation="Newlines can terminate a command and begin another in some parsing contexts.",
                defensive_notes="Normalize input (strip control chars) and avoid passing user data to shell contexts.",
            ),
            self._item(
                os_name="Linux/Unix",
                separator="`...`",
                template="[[SEP:backtick_substitution]] [[CMD_SUBST_PLACEHOLDER]]",
                description="Command substitution concept (backticks) — template only",
                bypass_explanation="Some shells evaluate substitutions before executing the full command.",
                defensive_notes="Avoid shell interpretation entirely. If unavoidable, apply strict allowlist validation and escape rules correctly (hard).",
            ),
            self._item(
                os_name="Linux/Unix",
                separator="$( ... )",
                template="[[SEP:dollar_paren_substitution]] [[CMD_SUBST_PLACEHOLDER]]",
                description="Command substitution concept ($()) — template only",
                bypass_explanation="$() is common in modern shells for substitution and may be expanded during parsing.",
                defensive_notes="Prefer safe APIs over filtering. Filtering metacharacters is brittle and bypassable.",
            ),
            self._item(
                os_name="Linux/Unix",
                separator=";",
                template=f"[[SEP:semicolon]] {cmd_file}",
                description="Sensitive file read concept (placeholder by default)",
                bypass_explanation="If input reaches a shell, attacker can chain a file-read command after a separator.",
                defensive_notes="Least privilege + sandboxing + no-shell. Don’t run apps with permissions that allow sensitive reads.",
            ),
        ]

    # -----------------------------
    # Windows patterns (templates)
    # -----------------------------
    def _windows_patterns(self):
        cmd_info = self._choose_cmd("info")
        cmd_file = self._choose_cmd("file")

        return [
            self._item(
                os_name="Windows",
                separator="&",
                template=f"[[SEP:ampersand]] {cmd_info}",
                description="Command chaining with & (cmd.exe style) — template only",
                bypass_explanation="`&` can chain commands; parsing differs between cmd.exe and PowerShell.",
                defensive_notes="Avoid invoking cmd.exe / powershell with user input. Use direct OS APIs or safe process spawning with fixed arguments.",
                note="Commands are placeholders unless explicitly enabled.",
            ),
            self._item(
                os_name="Windows",
                separator="|",
                template="[[SEP:pipe]] [[CMD_PLACEHOLDER]]",
                description="Pipe chaining concept — template only",
                bypass_explanation="Pipes can forward output to another command in some shells.",
                defensive_notes="Don’t rely on blocking `|`. Use safe APIs and argument arrays; avoid shells entirely.",
            ),
            self._item(
                os_name="Windows",
                separator="&&",
                template=f"[[SEP:and]] {cmd_info}",
                description="Conditional chaining with && — template only",
                bypass_explanation="Executes the next command only when the previous succeeds.",
                defensive_notes="Input filtering is bypassable. Design away the shell dependency.",
            ),
            self._item(
                os_name="Windows",
                separator="||",
                template=f"[[SEP:or]] {cmd_info}",
                description="Conditional chaining with || — template only",
                bypass_explanation="Executes the next command when the previous fails.",
                defensive_notes="Use strict allowlists, fixed argument arrays, and drop privileges.",
            ),
            self._item(
                os_name="Windows",
                separator="^",
                template="[[SEP:caret_escape]] [[ESCAPE_PLACEHOLDER]]",
                description="Escape/obfuscation concept in cmd.exe — template only",
                bypass_explanation="Some shells treat caret as an escape; naive filters may mis-tokenize it.",
                defensive_notes="Normalize input before validation. Best defense: don’t use shell parsing at all.",
            ),
            self._item(
                os_name="Windows",
                separator="\\n",
                template=f"[[SEP:newline]] {cmd_file}",
                description="Newline separation concept in script/batch-like contexts — placeholder by default",
                bypass_explanation="Control characters may be interpreted as delimiters depending on execution context.",
                defensive_notes="Strip control chars and enforce strict input formats. Use OS APIs for file reads instead of shelling out.",
            ),
        ]

    # -----------------------------
    # Bypass concepts (description-only)
    # -----------------------------
    def _bypass_concepts_description_only(self):
        return [
            {
                "type": "Command Injection",
                "subtype": "Bypass Concepts (description-only)",
                "os": "All",
                "separator": "N/A",
                "template": "[[DESCRIPTION_ONLY]]",
                "description": (
                    "Concepts attackers use to bypass weak filters: encoding/escaping tricks, quote insertion, "
                    "whitespace substitution, environment variables, and parser differences across shells."
                ),
                "bypass_explanation": (
                    "Denylist filters fail because shells have many equivalent syntaxes and multiple parsing stages. "
                    "Attackers adapt with alternate delimiters, encodings, and tokenization edge cases."
                ),
                "defensive_notes": (
                    "Primary defense is to avoid shell execution of user-controlled data. Use safe APIs, strict allowlists, "
                    "least privilege, and monitoring."
                ),
                "commands_enabled": self.enable_commands,
                "is_template": True,
                "labels": ["TEMPLATE_ONLY", "EDUCATIONAL", "NO_EXECUTION"],
                "note": "No concrete obfuscation payload strings are provided to remain pattern-based per scope.",
            }
        ]

    # -----------------------------
    # Defense Strategy (required explanation)
    # -----------------------------
    def _defense_strategy_item(self):
        return {
            "type": "Command Injection",
            "subtype": "Defense Strategy",
            "os": "All",
            "separator": "N/A",
            "template": "N/A",
            "description": "Why filters fail and how to prevent command injection",
            "bypass_explanation": (
                "Input filtering alone is unreliable because shells interpret many metacharacters, encodings, "
                "and syntaxes. Attackers can often find alternate representations that pass a denylist."
            ),
            "defensive_notes": (
                "SECURE CODING PRACTICES:\n"
                "1) Avoid invoking a shell with user input (no system(), shell=True, cmd.exe /c with user data)\n"
                "2) Use safe APIs with fixed argument arrays (e.g., subprocess.run([...], shell=False))\n"
                "3) If you must run OS commands: strict allowlist validation + fixed mapping (user choice -> known safe command)\n"
                "4) Run with least privilege; isolate with containers/sandbox where possible\n"
                "5) Normalize input (decode once, strip control chars) BEFORE validation\n"
                "6) Add monitoring: unusual metacharacters, spikes in errors, unexpected process spawning\n"
            ),
            "commands_enabled": self.enable_commands,
            "is_template": True,
            "labels": ["EDUCATIONAL"],
        }
