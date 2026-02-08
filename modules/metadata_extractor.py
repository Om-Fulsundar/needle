# modules/metadata_extractor.py

import os
from PyPDF2 import PdfReader

class MetadataExtractor:
    """
    Module 1: Metadata Extractor
    Purpose: Extract PDF metadata and detect anomalies.
    Runs only via main.py (no standalone execution).
    """

    def __init__(self, pdf_path: str):
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        self.pdf_path = pdf_path
        self.reader = PdfReader(pdf_path)

    def extract_metadata(self) -> dict:
        """Retrieve metadata as a dictionary."""
        metadata = self.reader.metadata or {}
        return {k: str(v) for k, v in metadata.items()}

    def analyze_metadata(self, meta_dict: dict) -> list:
        """Perform anomaly checks on metadata."""
        anomalies = []

        # Missing or empty author
        if "/Author" not in meta_dict or not meta_dict.get("/Author"):
            anomalies.append("Missing or empty Author field")

        # CreationDate == ModDate
        if "/CreationDate" in meta_dict and "/ModDate" in meta_dict:
            if meta_dict["/CreationDate"] == meta_dict["/ModDate"]:
                anomalies.append("CreationDate == ModDate (suspicious)")

        # Suspicious Creator/Producer values
        suspicious_values = ["anonymous", "unknown", "reportlab"]
        for key in ["/Creator", "/Producer"]:
            if key in meta_dict:
                val = meta_dict[key].lower()
                if any(s in val for s in suspicious_values):
                    anomalies.append(f"Suspicious {key} value: {meta_dict[key]}")

        return anomalies

    def run(self) -> dict:
        """Main entry point for the module."""
        meta = self.extract_metadata()
        anomalies = self.analyze_metadata(meta)
        return {
            "metadata": meta,
            "anomalies": anomalies
        }
