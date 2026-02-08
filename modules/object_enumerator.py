# modules/object_enumerator.py

import os
from PyPDF2 import PdfReader

class ObjectEnumerator:
    """
    Module 2: Object Enumerator
    Purpose: Scan page dictionaries for suspicious keys.
    """

    def __init__(self, pdf_path: str):
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        self.pdf_path = pdf_path
        self.reader = PdfReader(pdf_path)

        self.suspicious_keys = [
            "/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch",
            "/EmbeddedFile", "/Names", "/URI", "/SubmitForm", "/GoToE"
        ]

    def scan_page_dict(self, page, page_num: int) -> list:
        flagged = []
        try:
            raw_dict = str(page)
            for key in self.suspicious_keys:
                if key in raw_dict:
                    flagged.append({
                        "page": page_num,
                        "keyword": key,
                        "snippet": raw_dict[:300]
                    })
        except Exception as e:
            flagged.append({
                "page": page_num,
                "error": f"Failed to parse page dict: {str(e)}"
            })
        return flagged

    def run(self) -> dict:
        flagged_objects = []
        for i, page in enumerate(self.reader.pages):
            flagged_objects.extend(self.scan_page_dict(page, i + 1))

        return {
            "total_pages": len(self.reader.pages),
            "flagged_objects": flagged_objects
        }
