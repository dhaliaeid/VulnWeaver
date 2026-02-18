"""
Command Injection Module - Pattern-Based Study Generator

Reference: OWASP Command Injection
https://owasp.org/www-community/attacks/Command_Injection

PATTERN-BASED MODE — Strings demonstrate injection structure only.
Real OS commands are replaced with [COMMAND] placeholders so patterns
cannot execute as-is. Study the separator and bypass structure, not the command.

PLACEHOLDER NOTATION:
  [COMMAND]    — substitute with a shell command for lab testing only
  [ARG]        — substitute with a command argument or flag
  [FILE_PATH]  — substitute with a target file path in an authorised lab
  [IP]         — substitute with a target IP address
  [SEPARATOR]  — substitute with the chosen separator character
  [CHAR]       — substitute with a single character being obfuscated

All patterns are DISABLED BY DEFAULT.
No real OS commands are embedded. Study the separator/bypass structure only.
"""


class CMDIPayloadGenerator:
    """Generate pattern-based command injection study examples"""

    def __init__(self, os_type='linux'):
        self.os_type = os_type.lower()

    def generate_all_patterns(self):
        payloads = []
        if self.os_type in ('linux', 'both'):
            payloads.extend(self._generate_linux_patterns())
        if self.os_type in ('windows', 'both'):
            payloads.extend(self._generate_windows_patterns())
        payloads.extend(self._generate_bypass_patterns())
        payloads.extend(self._generate_why_filters_fail())
        return payloads

    # ------------------------------------------------------------------ #
    #  LINUX / UNIX PATTERNS                                               #
    # ------------------------------------------------------------------ #
    def _generate_linux_patterns(self):
        """
        Linux shell command-separator patterns.
        [COMMAND] is a placeholder — no real command is embedded.
        """
        return [
            {
                'type': 'Command Injection',
                'subtype': 'Separator — semicolon',
                'os': 'Linux/Unix',
                'pattern_structure': 'original_input ; [COMMAND]',
                'payload': '; [COMMAND]',
                'description': (
                    'PATTERN — Semicolon separator. '
                    'In shell, semicolons chain commands sequentially. '
                    'Both commands run regardless of each other\'s exit status. '
                    'If an application passes user input to a shell call, '
                    'appending ; [COMMAND] injects a second shell command.'
                ),
                'study_note': 'Replace [COMMAND] with a benign lab command (e.g. id) in an authorised environment only.',
                'bypass_explanation': 'Semicolons are not commonly filtered. Application likely uses system("ping "+input) or similar.',
                'defensive_notes': 'Never call system()/shell_exec() with user input. Use subprocess(args_list, shell=False) in Python.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — pipe',
                'os': 'Linux/Unix',
                'pattern_structure': 'original_input | [COMMAND]',
                'payload': '| [COMMAND]',
                'description': (
                    'PATTERN — Pipe separator. '
                    'Pipe passes stdout of the first command as stdin of [COMMAND]. '
                    'If the first command produces no output or fails, [COMMAND] '
                    'may still execute depending on shell settings.'
                ),
                'study_note': 'Replace [COMMAND] with a read-only lab command in an authorised environment only.',
                'bypass_explanation': 'Pipes are standard shell operators. Most applications using shell=True are vulnerable.',
                'defensive_notes': 'Use subprocess with a list of arguments. Validate that input matches expected format (e.g. IP address regex).',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — logical OR',
                'os': 'Linux/Unix',
                'pattern_structure': 'failing_input || [COMMAND]',
                'payload': 'INVALID_VALUE || [COMMAND]',
                'description': (
                    'PATTERN — Logical OR (||) separator. '
                    '|| executes [COMMAND] ONLY if the preceding command exits non-zero (fails). '
                    'Useful when the injected prefix will always fail (e.g. invalid host), '
                    'guaranteeing the injected command runs.'
                ),
                'study_note': 'INVALID_VALUE should be something that causes the original command to fail. Replace [COMMAND] in lab only.',
                'bypass_explanation': 'Attacker controls both sides: makes first command fail, ensures second runs.',
                'defensive_notes': 'Reject all shell metacharacters at input validation. Use safe API calls.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — logical AND',
                'os': 'Linux/Unix',
                'pattern_structure': 'valid_input && [COMMAND]',
                'payload': 'VALID_VALUE && [COMMAND]',
                'description': (
                    'PATTERN — Logical AND (&&) separator. '
                    '&& executes [COMMAND] ONLY if the preceding command exits zero (succeeds). '
                    'Attacker uses a valid prefix so the original command succeeds, '
                    'then chains the injected command.'
                ),
                'study_note': 'VALID_VALUE should be a value the application accepts. Replace [COMMAND] in lab only.',
                'bypass_explanation': 'Attacker crafts a valid-looking prefix that passes application logic, then appends &&.',
                'defensive_notes': 'Never concatenate user input into OS command strings. Allowlist expected input values.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — background ampersand',
                'os': 'Linux/Unix',
                'pattern_structure': 'original_input & [COMMAND]',
                'payload': '& [COMMAND]',
                'description': (
                    'PATTERN — Background execution (&). '
                    'Single & runs [COMMAND] in the background concurrently with the '
                    'original command. The HTTP response may not contain the output '
                    '(out-of-band execution); attacker may use DNS or HTTP callback instead.'
                ),
                'study_note': 'Out-of-band technique. Replace [COMMAND] with a callback-based command in authorised lab only.',
                'bypass_explanation': 'Background execution hides output from the response; harder to detect via response observation.',
                'defensive_notes': 'Use subprocess with shell=False. No input should reach a shell call.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Substitution — backtick',
                'os': 'Linux/Unix',
                'pattern_structure': '`[COMMAND]`',
                'payload': '`[COMMAND]`',
                'description': (
                    'PATTERN — Backtick command substitution. '
                    'The shell executes [COMMAND] inside backticks and substitutes '
                    'the result inline. Often used in attribute/URL contexts where '
                    'semicolons are blocked.'
                ),
                'study_note': 'Replace [COMMAND] in authorised lab only. Backtick substitution works in bash/sh.',
                'bypass_explanation': 'If ; and | are filtered, backtick substitution may still execute. Different metacharacter.',
                'defensive_notes': 'Block all shell metacharacters: ; | & ` $ ( ) { } < > \\ newline. Use safe subprocess API.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Substitution — $() modern syntax',
                'os': 'Linux/Unix',
                'pattern_structure': '$([COMMAND])',
                'payload': '$([COMMAND])',
                'description': (
                    'PATTERN — Modern $() command substitution. '
                    'Equivalent to backticks but nestable and preferred in modern shells. '
                    'Filters that block backticks often miss $().'
                ),
                'study_note': 'Replace [COMMAND] in authorised lab only. Works in bash, sh, zsh.',
                'bypass_explanation': 'Separate metacharacter from backtick; filters blocking ` may not block $(...).',
                'defensive_notes': 'Block $ ( ) in addition to other metacharacters. Use subprocess with shell=False.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — newline',
                'os': 'Linux/Unix',
                'pattern_structure': 'original_input\\n[COMMAND]',
                'payload': '\\n[COMMAND]',
                'description': (
                    'PATTERN — Newline (\\n) as command separator. '
                    'Shells interpret newlines as statement terminators, identical '
                    'to semicolons. Useful when ; is stripped but \\n is not.'
                ),
                'study_note': 'Replace [COMMAND] in authorised lab only. URL-encode as %0a for HTTP parameter injection.',
                'bypass_explanation': 'Filters stripping ; and | often forget newlines. %0a passes through URL decode and reaches the shell.',
                'defensive_notes': 'Strip all control characters including \\n \\r \\t from user input before any system call.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Redirection — input from file',
                'os': 'Linux/Unix',
                'pattern_structure': '[COMMAND]<[FILE_PATH]',
                'payload': '[COMMAND]<[FILE_PATH]',
                'description': (
                    'PATTERN — Input redirection without spaces. '
                    'The < operator redirects file contents as stdin to [COMMAND]. '
                    'Spaces are not required around < so space-filtering defences are bypassed.'
                ),
                'study_note': 'Replace [FILE_PATH] with a non-sensitive file in authorised lab only.',
                'bypass_explanation': 'Shell accepts redirection without whitespace; space-stripping filters miss this vector.',
                'defensive_notes': 'Block redirection operators < > >> in addition to command separators.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  WINDOWS PATTERNS                                                    #
    # ------------------------------------------------------------------ #
    def _generate_windows_patterns(self):
        """
        Windows cmd.exe command-separator patterns.
        [COMMAND] is a placeholder — no real command is embedded.
        """
        return [
            {
                'type': 'Command Injection',
                'subtype': 'Separator — ampersand (Windows)',
                'os': 'Windows',
                'pattern_structure': 'original_input & [COMMAND]',
                'payload': '& [COMMAND]',
                'description': (
                    'PATTERN — Windows cmd.exe & separator. '
                    'Single & runs both commands unconditionally, left then right. '
                    'Equivalent to Linux semicolon in cmd.exe context.'
                ),
                'study_note': 'Replace [COMMAND] in authorised Windows lab only.',
                'bypass_explanation': 'cmd.exe & is the primary unconditional separator. Most Windows shell injection uses this.',
                'defensive_notes': 'Use ProcessStartInfo with Arguments property, not cmd /c string. Validate input strictly.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — pipe (Windows)',
                'os': 'Windows',
                'pattern_structure': 'original_input | [COMMAND]',
                'payload': '| [COMMAND]',
                'description': (
                    'PATTERN — Windows pipe separator. '
                    'Passes stdout of the left command to stdin of [COMMAND]. '
                    'Identical function to Linux pipe.'
                ),
                'study_note': 'Replace [COMMAND] in authorised Windows lab only.',
                'bypass_explanation': 'Pipe works in both cmd.exe and PowerShell. Both must be considered as attack surfaces.',
                'defensive_notes': 'Reject | from user input. Use Windows API or .NET classes instead of shell invocation.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — logical AND (Windows)',
                'os': 'Windows',
                'pattern_structure': 'valid_input && [COMMAND]',
                'payload': 'VALID_VALUE && [COMMAND]',
                'description': (
                    'PATTERN — Windows cmd.exe && (logical AND). '
                    'Executes [COMMAND] only if the preceding command exits with code 0 (success).'
                ),
                'study_note': 'Replace VALID_VALUE with a passing input. Replace [COMMAND] in authorised lab only.',
                'bypass_explanation': 'Attacker uses a valid prefix so the first command succeeds, then appends &&.',
                'defensive_notes': 'Strip && and & from all user input destined for shell. Use safe API.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — logical OR (Windows)',
                'os': 'Windows',
                'pattern_structure': 'failing_input || [COMMAND]',
                'payload': 'INVALID_VALUE || [COMMAND]',
                'description': (
                    'PATTERN — Windows cmd.exe || (logical OR). '
                    'Executes [COMMAND] only if preceding command exits non-zero (fails).'
                ),
                'study_note': 'Replace INVALID_VALUE with something that causes the original command to fail.',
                'bypass_explanation': 'Attacker ensures first command fails to guarantee second command executes.',
                'defensive_notes': 'Block || in addition to | . Use validated process invocation without shell=True.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — caret escape (Windows)',
                'os': 'Windows',
                'pattern_structure': '[C]^[H]^[A]^[R]S of [COMMAND]',
                'payload': '[C]^[H]^[A]^[R] [C]^[O]^[M]^[M]^[A]^[N]^[D]',
                'description': (
                    'PATTERN — Windows caret (^) escape-character obfuscation. '
                    'cmd.exe treats ^ as an escape character that is stripped before execution. '
                    'Inserting ^ between characters of a command name bypasses string-matching '
                    'filters without affecting execution.'
                ),
                'study_note': 'Replace [C],[H],[A],[R] etc. with letters spelling the target command in an authorised lab only.',
                'bypass_explanation': 'cmd.exe strips ^ before interpreting the command line. wh^oa^mi executes as whoami.',
                'defensive_notes': 'Strip ^ from all input. Use ProcessStartInfo with explicit argument list, not cmd /c.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Separator — newline (Windows)',
                'os': 'Windows',
                'pattern_structure': 'original_input\\r\\n[COMMAND]',
                'payload': '\\r\\n[COMMAND]',
                'description': (
                    'PATTERN — CRLF as command separator in Windows batch context. '
                    'cmd.exe interprets carriage-return + newline as a line break, '
                    'starting a new command. Filters checking for & may miss \\r\\n.'
                ),
                'study_note': 'URL-encode as %0d%0a for HTTP parameter injection. Replace [COMMAND] in lab only.',
                'bypass_explanation': 'CRLF is a valid statement separator in batch; filters blocking metacharacters miss it.',
                'defensive_notes': 'Strip all control characters including \\r and \\n from input. Never use cmd /c with user input.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  BYPASS / OBFUSCATION PATTERNS                                       #
    # ------------------------------------------------------------------ #
    def _generate_bypass_patterns(self):
        """
        Filter evasion techniques applied to command injection.
        [COMMAND] and [CHAR] placeholders ensure no real command is embedded.
        Study the obfuscation structure — not the command itself.
        """
        return [
            {
                'type': 'Command Injection',
                'subtype': 'Bypass — quote insertion',
                'os': 'Linux/Unix',
                'pattern_structure': '; [C]"[H]"[A]"[R]"[S]',
                'payload': '; [C]"[H]"[A]"[R]"[S]',
                'description': (
                    'PATTERN — Double-quote insertion between command characters. '
                    'Bash ignores empty quoted strings ("") in command names. '
                    'Inserting " between each character breaks the word for string '
                    'matching but the shell reconstructs and executes the command.'
                ),
                'study_note': 'Replace each [CHAR] with one letter of the target command. Inert as printed — substitute in lab only.',
                'bypass_explanation': 'Bash: ec"ho" hi executes echo hi. Filters see gibberish; shell sees a valid command.',
                'defensive_notes': 'Block all quote characters in shell-bound input. Use subprocess with shell=False.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Bypass — IFS variable as space',
                'os': 'Linux/Unix',
                'pattern_structure': ';[C]${IFS}[COMMAND_ARGS]',
                'payload': ';[COMMAND]${IFS}[ARG]',
                'description': (
                    'PATTERN — $IFS (Internal Field Separator) substituted for space. '
                    '$IFS defaults to whitespace in bash. Inserting ${IFS} or $IFS '
                    'between command and argument bypasses filters that strip spaces.'
                ),
                'study_note': 'Replace [COMMAND] and [ARG] in authorised lab only. $IFS expands to a space/tab/newline.',
                'bypass_explanation': 'Filters strip space but leave $IFS intact; shell expands $IFS to a space before executing.',
                'defensive_notes': 'Block $ { } in addition to spaces. Use subprocess with arguments list.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Bypass — single-quote insertion',
                'os': 'Linux/Unix',
                'pattern_structure': ";[C]'[H]'[A]'[R]'[S]",
                'payload': ";[C]'[H]'[A]'[R]'[S]",
                'description': (
                    "PATTERN — Single-quote insertion between command characters. "
                    "Bash ignores adjacent empty single-quoted strings in command names. "
                    "'w'h'o'a'm'i executes as whoami. "
                    'Same technique as double-quote insertion but uses apostrophe.'
                ),
                'study_note': 'Replace each [CHAR] with one letter of target command in lab only.',
                'bypass_explanation': "Shell concatenates 'w'h'o'a'm'i as whoami. Filters that block \" may not block '.",
                'defensive_notes': "Block both ' and \" in shell-bound input. Safe subprocess API makes this irrelevant.",
            },
            {
                'type': 'Command Injection',
                'subtype': 'Bypass — backslash escape',
                'os': 'Linux/Unix',
                'pattern_structure': r'; \[C]\[H]\[A]\[R]\[S]',
                'payload': r'; \[C]\[H]\[A]\[R]\[S]',
                'description': (
                    'PATTERN — Backslash inserted between command characters. '
                    r'Bash: \w\h\o\a\m\i executes as whoami — backslash escapes '
                    'each character to itself, resulting in the original character. '
                    'Breaks keyword detection while remaining executable.'
                ),
                'study_note': r'Replace each [CHAR] with one letter preceded by \. In lab only.',
                'bypass_explanation': r'Bash interprets \c as c for most characters. Filters see backslashes; shell sees the command.',
                'defensive_notes': r'Block \ (backslash) in shell-bound input. Use subprocess with shell=False.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Bypass — variable substitution',
                'os': 'Linux/Unix',
                'pattern_structure': '; X=[CHAR];Y=[CHAR];$X$Y[COMMAND_REMAINDER]',
                'payload': '; A=[CHAR];B=[CHAR];$A$B[COMMAND_SUFFIX]',
                'description': (
                    'PATTERN — Shell variable assembly to construct command name. '
                    'Sets shell variables to individual characters then expands them '
                    'to form the command name at execution time. '
                    'No complete command word appears in the injected string.'
                ),
                'study_note': 'Replace [CHAR] with individual letters. The assembled $A$B... forms the command name. Lab use only.',
                'bypass_explanation': 'Command name is never present as a literal string; assembled at runtime from variables. WAF keyword lists cannot match it.',
                'defensive_notes': 'All variable-expansion chars ($ { }) must be rejected. Only subprocess with shell=False is immune.',
            },
            {
                'type': 'Command Injection',
                'subtype': 'Bypass — Windows caret per character',
                'os': 'Windows',
                'pattern_structure': '[C]^[H]^[A]^[R]^[S] [ARG]',
                'payload': '[C]^[H]^[A]^[R]^[S] [ARG]',
                'description': (
                    'PATTERN — Windows caret (^) inserted between every character. '
                    'cmd.exe strips ^ before interpreting the command name. '
                    'Inserting ^ after every character breaks all keyword signatures '
                    'while the shell reconstructs the original command.'
                ),
                'study_note': 'Replace each [CHAR] with a letter of the target command, separated by ^. Lab only.',
                'bypass_explanation': 'cmd.exe strips ^; the reconstructed string is the original command. No WAF keyword can match the fragmented form.',
                'defensive_notes': 'Strip ^ from all Windows shell-bound input. Use ProcessStartInfo with Arguments — not cmd /c.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  WHY FILTERS FAIL — STUDY REFERENCE                                  #
    # ------------------------------------------------------------------ #
    def _generate_why_filters_fail(self):
        """
        Conceptual study entries explaining root causes — no payload strings.
        """
        return [
            {
                'type': 'Command Injection',
                'subtype': 'Study Reference — why denylist filters fail',
                'os': 'All',
                'payload': 'N/A — Conceptual study entry',
                'description': (
                    'STUDY REFERENCE — Root cause analysis: why input filters fail against command injection.\n\n'
                    '1. INCOMPLETE SEPARATOR LIST\n'
                    '   Filters block ; and | but miss & && || newline backtick $()\n\n'
                    '2. NO NORMALISATION BEFORE FILTERING\n'
                    '   Encoded input (%0a, %26) is decoded AFTER the filter runs.\n\n'
                    '3. COMMAND RECONSTRUCTION TECHNIQUES\n'
                    '   Quotes, carets, backslashes, $IFS, variables all allow command\n'
                    '   names to be assembled at shell-parse time, invisible to the filter.\n\n'
                    '4. CONTEXT BLINDNESS\n'
                    '   Filters applied at HTTP layer do not understand shell grammar.\n'
                    '   A filter that blocks "whoami" has no concept of w"h"oami or who$IFS$9ami.\n\n'
                    '5. ROOT FIX\n'
                    '   Never pass user input to a shell. Use subprocess(args, shell=False)\n'
                    '   or equivalent language-level safe API. If unavoidable, validate\n'
                    '   against a strict allowlist of expected values (e.g. IP address regex).'
                ),
                'study_note': 'No placeholder substitution needed — this is a conceptual reference entry.',
                'bypass_explanation': 'Denylist approaches are fundamentally unable to enumerate all bypass techniques.',
                'defensive_notes': (
                    'SECURE CODING SUMMARY:\n'
                    '  Python  : subprocess.run([cmd, arg1, arg2], shell=False)\n'
                    '  Node.js : execFile(cmd, [args])  — not exec()\n'
                    '  Java    : ProcessBuilder(List.of(cmd, arg))\n'
                    '  .NET    : ProcessStartInfo { FileName=cmd, Arguments=arg }\n'
                    '  PHP     : escapeshellarg() on each arg — but avoid shell if possible'
                ),
            },
        ]