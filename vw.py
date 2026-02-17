#!/usr/bin/env python3
"""
Payload Generation Framework - Educational Security Tool
ITSOLERA (PVT) LTD - Offensive Security Internship Task

ETHICAL DISCLAIMER:
This tool is developed strictly for educational, defensive, and authorized
penetration testing environments. Any misuse outside legal authorization is
strictly prohibited and may be illegal.

Aligned with OWASP Code of Ethics:
https://owasp.org/www-project-code-of-ethics/

Author: Security Research Team
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

class PayloadFramework:
    """Main framework class orchestrating payload generation"""

    def __init__(self):
        self.encoder = PayloadEncoder()
        self.export_handler = ExportHandler()

    def generate_payloads(self, args):
        """Generate payloads based on command-line arguments"""
        payloads = []

        # XSS Module — runs for 'xss' or 'all'
        if args.module in ('xss', 'all'):
            xss_gen = XSSPayloadGenerator()
            payloads.extend(xss_gen.generate_all_contexts())

        # SQLi Module — runs for 'sqli' or 'all'
        # BUG FIX: was 'elif', so sqli/cmdi were silently skipped under --module all
        if args.module in ('sqli', 'all'):
            sqli_gen = SQLiPayloadGenerator(db_type=args.db)
            payloads.extend(sqli_gen.generate_all_types())

        # Command Injection Module — runs for 'cmdi' or 'all'
        if args.module in ('cmdi', 'all'):
            cmdi_gen = CMDIPayloadGenerator(os_type=args.os)
            payloads.extend(cmdi_gen.generate_all_patterns())

        # Normalise payload dicts — accept 'payload' or 'template' as the
        # key that holds the actual payload string. Also map common
        # alternative field names so the rest of the pipeline is uniform.
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

    def _display_payloads(self, payloads):
        """Display generated payloads to console"""
        print("\n" + "=" * 80)
        print(" GENERATED PAYLOAD TEMPLATES (EDUCATIONAL USE ONLY)")
        print("=" * 80 + "\n")

        for idx, p in enumerate(payloads, 1):
            print(f"[{idx}] Type: {p.get('type', 'N/A')}")
            print(f"    Context:     {p.get('context', 'N/A')}")
            print(f"    Description: {p.get('description', 'N/A')}")
            print(f"    Payload:     {p['payload']}")

            if 'encoded_payload' in p:
                print(f"    Encoded ({p['encoding_type']}): {p['encoded_payload']}")

            if 'bypass_explanation' in p:
                print(f"    Bypass Logic: {p['bypass_explanation']}")

            if 'defensive_notes' in p:
                print(f"    Defense: {p['defensive_notes']}")

            print("-" * 80)

    def _get_obfuscation_notes(self, obf_type):
        """Return obfuscation technique explanation"""
        notes = {
            'comment':    'Comment insertion breaks signature-based detection',
            'whitespace': 'Whitespace abuse exploits poor tokenization',
            'mixed':      'Mixed encoding bypasses single-pass decoders',
        }
        return notes.get(obf_type, 'Custom obfuscation applied')


def main():
    """Main entry point with argument parsing"""

    # Display banner
    banner = """

 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗██████╗
 ██║   ██║██║   ██║██║     ████╗  ██║    ██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
 ██║   ██║██║   ██║██║     ██╔██╗ ██║    ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  ██████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝     ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
  
    Educational Payload Generation Framework - Authorized Testing Only
    AUTHOR: Dalia Ibrahim
    """
    print(banner)
    print("\n" + "=" * 80)

    parser = argparse.ArgumentParser(
        description='Educational Payload Generation Framework',
        epilog='Example: python payload_gen.py --module xss --encode url --output payloads.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

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
        choices=['mysql', 'postgresql', 'mssql'],
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
    parser.add_argument('--output',  help='Output file path for export')
    parser.add_argument(
        '--format',
        choices=['json', 'txt', 'csv'],
        default='json',
        help='Export format'
    )
    parser.add_argument('--burp',     action='store_true', help='Export in Burp Suite format')
    parser.add_argument('--examples', action='store_true', help='Show usage examples and exit')

    args = parser.parse_args()

    if args.examples:
        show_examples()
        sys.exit(0)

    if not args.module:
        parser.error('the --module argument is required')

    framework = PayloadFramework()

    try:
        payloads = framework.generate_payloads(args)
        print(f"\n[✓] Generated {len(payloads)} payload templates successfully")
        print("\n[!] REMINDER: These are educational templates for authorized testing only!")

    except KeyError as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


def show_examples():
    """Display usage examples"""
    print("""
USAGE EXAMPLES:
===============

1. Generate XSS payloads with URL encoding:
   python payload_gen.py --module xss --encode url

2. Generate MySQL SQLi payloads and export to JSON:
   python payload_gen.py --module sqli --db mysql --output sqli_payloads.json

3. Generate all payloads with Base64 encoding:
   python payload_gen.py --module all --encode base64 --output all_payloads.txt --format txt

4. Generate Windows command injection patterns:
   python payload_gen.py --module cmdi --os windows --output cmdi.json

5. Generate obfuscated XSS payloads:
   python payload_gen.py --module xss --obfuscate comment --output obf_xss.json

6. Export for Burp Suite integration:
   python payload_gen.py --module sqli --burp --output burp_payloads.json

ETHICAL REMINDER:
=================
Always obtain written authorization before testing.
Unauthorized access is illegal and unethical.
Use only in lab environments or with explicit permission.
""")


if __name__ == '__main__':
    main()