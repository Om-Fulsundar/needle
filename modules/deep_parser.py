# modules/deep_parser.py

import os
import re

class DeepParser:
    """
    Module 4: Deep Parser
    Purpose: Scan raw PDF bytes for suspicious object streams and extract payloads.
    """

    def __init__(self, pdf_path: str):
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        self.pdf_path = pdf_path

        # Suspicious markers to look for
        self.suspicious_patterns = {
            "JavaScript": re.compile(r"/JavaScript\s+(\(.*?\))", re.DOTALL),
            "JS": re.compile(r"/JS\s+(\(.*?\))", re.DOTALL),
            "URI": re.compile(r"/URI\s*\((.*?)\)", re.DOTALL),
            "Launch": re.compile(r"/Launch\s+(\(.*?\))", re.DOTALL),
            "EmbeddedFile": re.compile(r"/EmbeddedFile", re.DOTALL),
            "OpenAction": re.compile(r"/OpenAction", re.DOTALL),
        }

    def run(self) -> dict:
        with open(self.pdf_path, "rb") as f:
            raw_bytes = f.read()

        raw_text = raw_bytes.decode(errors="ignore")
        extracted = []

        for label, pattern in self.suspicious_patterns.items():
            matches = pattern.findall(raw_text)
            for m in matches:
                extracted.append({
                    "type": label,
                    "snippet": m[:200] if isinstance(m, str) else str(m)[:200]
                })

        return {
            "total_payloads": len(extracted),
            "extracted_payloads": extracted
        }
