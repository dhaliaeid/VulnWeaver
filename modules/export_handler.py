"""
Export Handler - Output payload/templates in various formats
"""

import json
import csv


class ExportHandler:
    def export(self, payloads, output_path, format_type="json"):
        if format_type == "json":
            self._export_json(payloads, output_path)
        elif format_type == "txt":
            self._export_txt(payloads, output_path)
        elif format_type == "csv":
            self._export_csv(payloads, output_path)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _export_json(self, payloads, output_path):
        output = {
            "metadata": {
                "tool": "VulnWeaver",
                "warning": "Educational use only. Authorized labs only.",
                "count": len(payloads),
            },
            "items": payloads,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

    def _export_txt(self, payloads, output_path):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("VulnWeaver - Payload/Template Catalog (Educational)\n")
            f.write("WARNING: Authorized labs only\n")
            f.write("=" * 80 + "\n\n")

            for idx, p in enumerate(payloads, 1):
                f.write(f"[{idx}] {p.get('type','N/A')} - {p.get('subtype','N/A')}\n")
                f.write(f"Context: {p.get('context','N/A')}\n")
                if p.get("db_type"):
                    f.write(f"DB: {p.get('db_type')}\n")
                if p.get("os"):
                    f.write(f"OS: {p.get('os')}\n")

                f.write(f"Description: {p.get('description','N/A')}\n")

                if p.get("template"):
                    f.write("\nTEMPLATE:\n")
                    f.write(p["template"] + "\n")

                if p.get("payload"):
                    f.write("\nPAYLOAD:\n")
                    f.write(p["payload"] + "\n")

                if p.get("encoded_payload"):
                    f.write(f"\nENCODED ({p.get('encoding_type','N/A')}):\n")
                    f.write(p["encoded_payload"] + "\n")

                if p.get("bypass_explanation"):
                    f.write("\nBYPASS:\n")
                    f.write(p["bypass_explanation"] + "\n")

                if p.get("defensive_notes"):
                    f.write("\nDEFENSE:\n")
                    f.write(p["defensive_notes"] + "\n")

                if p.get("note"):
                    f.write("\nNOTE:\n")
                    f.write(p["note"] + "\n")

                f.write("\n" + "-" * 80 + "\n\n")

    def _export_csv(self, payloads, output_path):
        if not payloads:
            return
        all_fields = set()
        for p in payloads:
            all_fields.update(p.keys())
        fieldnames = sorted(all_fields)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(payloads)

    def export_burp_format(self, payloads, output_path):
        """
        Burp Intruder payload list (one payload per line).
        Preference order:
          encoded_payload -> payload
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# Burp Suite Payload List (Educational)\n")
            f.write("# VulnWeaver\n\n")
            for p in payloads:
                line = p.get("encoded_payload") or p.get("payload")
                if line:
                    f.write(str(line).strip() + "\n")
