# modules/keyword_scanner.py

import os

class KeywordScanner:
    """
    Module 3: Keyword Scanner
    Purpose: Scan raw PDF bytes for suspicious keywords and count frequency.
    """

    def __init__(self, pdf_path: str):
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        self.pdf_path = pdf_path

        # Keywords commonly used in malicious PDFs
        self.suspicious_keywords = [
            "/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch",
            "/EmbeddedFile", "/Names", "/URI", "/SubmitForm", "/GoToE",
            "/RichMedia", "/Movie", "/Sound", "/Action"
        ]

    def run(self) -> dict:
        """Main entry point for the module."""
        with open(self.pdf_path, "rb") as f:
            raw_bytes = f.read()

        raw_text = raw_bytes.decode(errors="ignore")

        keyword_hits = {}
        for keyword in self.suspicious_keywords:
            count = raw_text.count(keyword)
            if count > 0:
                keyword_hits[keyword] = count

        return {
            "total_keywords_detected": len(keyword_hits),
            "keyword_hits": keyword_hits
        }
