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
"""

import argparse
import sys
from textwrap import indent

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
        payloads = []

        # Generate modules
        if args.module in ("xss", "all"):
            xss_gen = XSSPayloadGenerator()
            payloads.extend(xss_gen.generate_all_contexts())

        if args.module in ("sqli", "all"):
            sqli_gen = SQLiPayloadGenerator(db_type=args.db)
            payloads.extend(sqli_gen.generate_all_types())

        if args.module in ("cmdi", "all"):
            cmdi_gen = CMDIPayloadGenerator(os_type=args.os)
            payloads.extend(cmdi_gen.generate_all_patterns())

        # Normalize records safely (keep both template + payload if present)
        normalized = []
        for i, p in enumerate(payloads):
            if not isinstance(p, dict):
                raise TypeError(f"Payload at index {i} is not a dict: {type(p)}")

            item = dict(p)  # copy

            # Normalize type/description
            item.setdefault("type", item.get("module", item.get("category", "N/A")))
            item.setdefault("description", item.get("title", item.get("name", "N/A")))

            # Normalize template/payload separation
            # - template: multi-line educational block (if provided)
            # - payload: the string you actually test/export as a single payload
            template = item.get("template", "")
            payload_str = item.get("payload", "")

            # If module only provides template (like your tokenized XSS), keep it but don't force it into payload
            item["template"] = template if template else ""
            item["payload"] = payload_str if payload_str else ""

            # If mode=lab, convert tokenized XSS templates into safe proof payloads (minimal)
            # This does NOT send requests; it only outputs strings for DVWA/Juice Shop testing.
            if args.mode == "lab" and item.get("type") == "XSS":
                # If there is no real payload string, provide a harmless proof string
                # You can later improve this mapping to be context-specific.
                if not item["payload"]:
                    item["payload"] = '<img src=x onerror=alert(1)>'
                item["lab_note"] = "LAB_MODE: harmless proof payload for DVWA/Juice Shop screenshots"

            normalized.append(item)

        payloads = normalized

        # Apply encoding if requested
        if args.encode != "none":
            for p in payloads:
                if p.get("payload"):
                    p["encoded_payload"] = self.encoder.encode(p["payload"], args.encode)
                    p["encoding_type"] = args.encode

        # Obfuscation note (your project requirement says “demonstration”, not real mutation)
        if args.obfuscate:
            note = self._get_obfuscation_notes(args.obfuscate)
            for p in payloads:
                p["obfuscation_notes"] = note

        # Display
        self._display_payloads(payloads)

        # Export
        if args.output:
            # If your ExportHandler supports extra args, pass them; otherwise remove burp_mode.
            self.export_handler.export(payloads, args.output, args.format, burp_mode=args.burp)
            print(f"\n[+] Payloads exported to: {args.output}")

        return payloads

    def _display_payloads(self, payloads):
        print("\n" + "=" * 80)
        print("GENERATED PAYLOAD OUTPUT (EDUCATIONAL USE ONLY)")
        print("=" * 80 + "\n")

        for idx, p in enumerate(payloads, 1):
            print(f"[{idx}]")
            print(f"Type:        {p.get('type', 'N/A')}")
            print(f"Context:     {p.get('context', 'N/A')}")
            print(f"Description: {p.get('description', 'N/A')}")

            # Show payload (single string)
            if p.get("payload"):
                print("Payload:")
                print(indent(p["payload"], "  "))

            # Show template (multi-line) if present
            if p.get("template"):
                print("Template:")
                print(indent(p["template"], "  "))

            if "encoded_payload" in p:
                print(f"Encoded ({p.get('encoding_type','N/A')}):")
                print(indent(p["encoded_payload"], "  "))

            if p.get("bypass_explanation"):
                print("Bypass Logic:")
                print(indent(str(p["bypass_explanation"]), "  "))

            if p.get("defensive_notes"):
                print("Defense:")
                print(indent(str(p["defensive_notes"]), "  "))

            if p.get("lab_note"):
                print("Note:")
                print(indent(p["lab_note"], "  "))

            print("-" * 80)

    def _get_obfuscation_notes(self, obf_type):
        notes = {
            "comment": "Comment insertion breaks signature-based detection",
            "whitespace": "Whitespace abuse exploits poor tokenization",
            "mixed": "Mixed encoding bypasses single-pass decoders",
        }
        return notes.get(obf_type, "Custom obfuscation applied")


def main():
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
        description="Educational Payload Generation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--module", choices=["xss", "sqli", "cmdi", "all"], help="Payload module to use")
    parser.add_argument("--mode", choices=["template", "lab"], default="template",
                        help="Output mode: template (default) or lab (DVWA/Juice Shop proof strings)")
    parser.add_argument("--encode", choices=["url", "base64", "hex", "none"], default="none", help="Encoding type")
    parser.add_argument("--db", choices=["mysql", "postgresql", "mssql"], default="mysql", help="DB type for SQLi")
    parser.add_argument("--os", choices=["linux", "windows", "both"], default="linux", help="OS for command injection")
    parser.add_argument("--obfuscate", choices=["comment", "whitespace", "mixed"], help="Obfuscation demo note")
    parser.add_argument("--output", help="Output file path for export")
    parser.add_argument("--format", choices=["json", "txt", "csv"], default="json", help="Export format")
    parser.add_argument("--burp", action="store_true", help="Export in Burp Suite compatible format")
    parser.add_argument("--examples", action="store_true", help="Show usage examples and exit")

    args = parser.parse_args()

    if args.examples:
        print("Example: python vw.py --module xss --mode lab --output xss.json --format json")
        sys.exit(0)

    if not args.module:
        parser.error("the --module argument is required")

    framework = PayloadFramework()

    try:
        payloads = framework.generate_payloads(args)
        print(f"\n[✓] Generated {len(payloads)} items successfully")
        if args.mode == "lab":
            print("[!] LAB MODE enabled: outputs are for DVWA/Juice Shop proof screenshots only.")
    except Exception as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
