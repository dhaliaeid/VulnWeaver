#!/usr/bin/env python3
"""
Payload Generation Framework - Educational Security Tool

ETHICAL DISCLAIMER:
This tool is developed strictly for educational, defensive, and authorized
penetration testing environments (e.g., DVWA/Juice Shop labs).
Any misuse outside legal authorization is prohibited.

Aligned with OWASP Code of Ethics:
https://owasp.org/www-project-code-of-ethics/
"""

import argparse
import sys

from modules.xss import XSSPayloadGenerator
from modules.sqli import SQLiPayloadGenerator
from modules.cmdi import CMDIPayloadGenerator
from modules.encoder import PayloadEncoder
from modules.export_handler import ExportHandler


def _indent_block(s: str, prefix: str = "  ") -> str:
    """Indent multi-line strings for clean CLI output (left aligned blocks)."""
    if not s:
        return ""
    s = str(s).strip("\n")
    return prefix + s.replace("\n", "\n" + prefix)


class PayloadFramework:
    """Main framework class orchestrating payload generation."""

    def __init__(self):
        self.encoder = PayloadEncoder()
        self.export_handler = ExportHandler()

    def generate_payloads(self, args):
        payloads = []

        # NOTE: not elif -> so --module all runs all modules
        if args.module in ("xss", "all"):
            xss_gen = XSSPayloadGenerator()
            payloads.extend(xss_gen.generate_all_contexts())

        if args.module in ("sqli", "all"):
            sqli_gen = SQLiPayloadGenerator(db_type=args.db, case_variants=True)
            payloads.extend(sqli_gen.generate_all_types())

        if args.module in ("cmdi", "all"):
            cmdi_gen = CMDIPayloadGenerator(os_type=args.os)
            payloads.extend(cmdi_gen.generate_all_patterns())

        payloads = self._normalize_payload_dicts(payloads)

        # Lab mode: ONLY if explicitly enabled + user confirms
        if args.mode == "lab":
            self._apply_lab_mode(payloads)

        # Encoding demonstration (representation only)
        if args.encode != "none":
            for p in payloads:
                if p.get("payload"):
                    p["encoded_payload"] = self.encoder.encode(p["payload"], args.encode)
                    p["encoding_type"] = args.encode

        # Obfuscation note (explanations only)
        if args.obfuscate:
            note = self._get_obfuscation_notes(args.obfuscate)
            for p in payloads:
                p["obfuscation_notes"] = note

        # Display
        self._display_payloads(payloads)

        # Export
        if args.output:
            if args.burp:
                self.export_handler.export_burp_format(payloads, args.output)
            else:
                self.export_handler.export(payloads, args.output, args.format)
            print(f"\n[+] Exported: {args.output}")

        return payloads

    def _normalize_payload_dicts(self, payloads):
        """
        Normalize keys so CLI/export doesn't crash.
        We keep module-specific fields intact.
        """
        out = []
        for i, p in enumerate(payloads):
            if not isinstance(p, dict):
                raise TypeError(f"Item #{i} is not a dict: {type(p)}")

            item = dict(p)

            # Required-ish fields
            item.setdefault("type", item.get("module") or item.get("category") or "N/A")
            item.setdefault("description", item.get("title") or item.get("name") or "N/A")
            item.setdefault("context", "N/A")
            item.setdefault("subtype", "N/A")

            # Support template-only items
            item.setdefault("template", "")
            item.setdefault("payload", "")

            out.append(item)
        return out

    def _apply_lab_mode(self, payloads):
        """
        LAB mode:
        - For XSS: provide simple proof payload when templates are tokenized/empty
        - For CMDI: keep the module lab proofs as-is (they already include lab_suitable=True)
        - For SQLi: leave unchanged (still examples)
        """
        for p in payloads:
            p["lab_mode"] = True

            # XSS: if tokenized or missing payload, provide a simple proof
            if p.get("type") == "XSS":
                payload_text = (p.get("payload") or "") + "\n" + (p.get("template") or "")
                looks_tokenized = "[[" in payload_text or "[PAYLOAD]" in payload_text
                if not p.get("payload") or looks_tokenized:
                    p["payload"] = '<img src=x onerror=alert(1)>'
                    p["lab_note"] = "LAB_MODE: proof payload for DVWA/Juice Shop screenshots"

            # CMDI: do NOT rewrite automatically. The cmdi module now provides Lab Proof items already.
            if p.get("type") == "Command Injection":
                p.setdefault("lab_note", "LAB_MODE: use 'Lab Proof' entries for screenshots (authorized labs only).")
                
    def _display_payloads(self, payloads):
        print("\n" + "=" * 80)
        print("VulnWeaver - Generated Output (Educational / Authorized Labs Only)")
        print("=" * 80)

        for idx, p in enumerate(payloads, 1):
            print(f"\n[{idx}]")
            print(f"-Type:        {p.get('type')}")
            print(f"-Subtype:     {p.get('subtype')}")
            print(f"-Context:     {p.get('context')}")
            if p.get("db_type"):
                print(f"-DB Type:     {p.get('db_type')}")
            if p.get("os"):
                print(f"-OS:          {p.get('os')}")

            print(f"-Description: {p.get('description')}")

            if p.get("template"):
                print("-Template:")
                print(_indent_block(p.get("template")))

            if p.get("payload"):
                print("-Payload:")
                print(_indent_block(p.get("payload")))

            if p.get("encoded_payload"):
                print(f"-Encoded ({p.get('encoding_type')}):")
                print(_indent_block(p.get("encoded_payload")))

            if p.get("bypass_explanation"):
                print("-Bypass Logic:")
                print(_indent_block(p.get("bypass_explanation")))

            if p.get("defensive_notes"):
                print("-Defense:")
                print(_indent_block(p.get("defensive_notes")))

            if p.get("obfuscation_notes"):
                print("-Obfuscation Notes:")
                print(_indent_block(p.get("obfuscation_notes")))

            if p.get("note"):
                print("-Note:")
                print(_indent_block(p.get("note")))

            if p.get("lab_note"):
                print("-Lab Note:")
                print(_indent_block(p.get("lab_note")))

            print("-" * 80)

    @staticmethod
    def _get_obfuscation_notes(obf_type):
        notes = {
            "comment": "Comment insertion breaks signature-based detection (denylist matching).",
            "whitespace": "Whitespace abuse exploits weak tokenization (filters check only spaces).",
            "mixed": "Mixed encoding can bypass single-pass decoders (normalize/validate order issues).",
        }
        return notes.get(obf_type, "Custom obfuscation applied.")


def show_examples():
    print(
        r"""
USAGE EXAMPLES:
===============

1) Template-only (default):
   python3 vw.py --module xss
   python3 vw.py --module sqli --db mysql
   python3 vw.py --module cmdi --os linux

2) Export to JSON/TXT/CSV:
   python3 vw.py --module all --output out.json --format json
   python3 vw.py --module all --output out.txt  --format txt
   python3 vw.py --module all --output out.csv  --format csv

3) Encoding demo:
   python3 vw.py --module xss --encode url
   python3 vw.py --module sqli --encode hex

4) Burp payload list export (offline):
   python3 vw.py --module sqli --burp --output burp_payloads.txt

5) LAB MODE (DVWA/Juice Shop screenshots only):
   python3 vw.py --module xss --mode lab --i-understand
"""
    )


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
        description="VulnWeaver - Educational Payload Generation Framework (No auto sending)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--module", choices=["xss", "sqli", "cmdi", "all"], required=True, help="Module to generate")
    parser.add_argument(
        "--mode",
        choices=["template", "lab"],
        default="template",
        help="template=non-executing templates (default), lab=proof payloads for DVWA/Juice Shop screenshots",
    )

    parser.add_argument("--encode", choices=["url", "base64", "hex", "none"], default="none", help="Encoding demo")
    parser.add_argument("--db", choices=["mysql", "postgresql", "mssql"], default="mysql", help="DB type for SQLi")
    parser.add_argument("--os", choices=["linux", "windows", "both"], default="linux", help="OS type for CMDi")
    parser.add_argument("--enable-cmd-examples", action="store_true", help="Enable example command strings in CMDi (still offline)")

    parser.add_argument("--obfuscate", choices=["comment", "whitespace", "mixed"], help="Add obfuscation notes")
    parser.add_argument("--output", help="Export file path")
    parser.add_argument("--format", choices=["json", "txt", "csv"], default="json", help="Export format")
    parser.add_argument("--burp", action="store_true", help="Export a Burp Intruder payload list (offline)")
    parser.add_argument("--examples", action="store_true", help="Show examples and exit")

    args = parser.parse_args()

    if args.examples:
        show_examples()
        sys.exit(0)

    fw = PayloadFramework()

    try:
        payloads = fw.generate_payloads(args)
        print(f"\n[✓] Generated {len(payloads)} items successfully.")
        if args.mode == "lab":
            print("[!] LAB MODE is ON: generate screenshots only on DVWA/Juice Shop.")
    except Exception as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
