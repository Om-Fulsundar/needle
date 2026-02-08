# modules/ioc_extractor.py

import os
import re

class IOCExtractor:
    """
    Module 5: IOC Extractor (strict domains + path length filter)
    Purpose: Extract Indicators of Compromise (IOCs) with strict domain rules and ignore overly long paths.
    """

    def __init__(self, pdf_path: str, payloads: list = None):
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        self.pdf_path = pdf_path
        self.payloads = payloads or []

        # Regex patterns
        self.patterns = {
            # Strict domain endings only
            "domains": re.compile(
                r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|gov|edu|mil|info|biz|io|co|us|uk|de|fr|ru|cn|in|jp|au|ca|xyz)\b"
            ),
            "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "emails": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            "file_paths": re.compile(r"(?:[A-Za-z]:\\\\[^\s]+|/[^ \n]+)"),
            "registry_keys": re.compile(r"HKEY_[A-Z_]+\\\\[^\s]+")
        }

        # Max path length to avoid noise
        self.max_path_length = 120

    def run(self) -> dict:
        # Combine payload snippets first
        text_data = "\n".join(
            [p.get("snippet", "") for p in self.payloads if isinstance(p, dict)]
        )

        # Fallback: also scan raw PDF
        with open(self.pdf_path, "rb") as f:
            raw_text = f.read().decode(errors="ignore")
        text_data += "\n" + raw_text

        iocs = {}
        for label, pattern in self.patterns.items():
            matches = pattern.findall(text_data)
            if matches:
                cleaned = []
                for m in matches:
                    m = m.strip()
                    if label == "domains":
                        # Skip garbage domains (short prefix like "a.com")
                        if len(m.split(".")[0]) < 3:
                            continue
                    if label == "file_paths":
                        # Skip overly long paths (noise)
                        if len(m) > self.max_path_length:
                            continue
                    cleaned.append(m)
                if cleaned:
                    iocs[label] = list(set(cleaned))  # unique values

        return {
            "total_iocs": sum(len(v) for v in iocs.values()),
            "iocs": iocs
        }
