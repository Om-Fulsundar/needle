# main.py
# script by Om Fulsundar (https://github.com/Om-Fulsundar)

import json
import sys
import os

# Import modules
from modules.metadata_extractor import MetadataExtractor
from modules.object_enumerator import ObjectEnumerator
from modules.keyword_scanner import KeywordScanner
from modules.deep_parser import DeepParser
from modules.ioc_extractor import IOCExtractor
from modules.risk_engine import RiskEngine
from modules.report import generate_report


def run_analysis(pdf_path: str) -> dict:
    """
    Orchestrates all Needle modules on the given PDF.
    Returns a unified dictionary of results.
    """
    results = {}

    # Run modules
    results["metadata"] = MetadataExtractor(pdf_path).run()
    results["objects"] = ObjectEnumerator(pdf_path).run()
    results["keywords"] = KeywordScanner(pdf_path).run()
    results["deep_parse"] = DeepParser(pdf_path).run()
    results["iocs"] = IOCExtractor(pdf_path, results["deep_parse"].get("extracted_payloads")).run()
    results["risk"] = RiskEngine(results).run()

    # Generate formatted report
    report_text = generate_report(results)
    results["report"] = report_text

    return results


def save_report(report_text: str, pdf_path: str):
    """
    Saves the report to results/ folder with filename based on PDF name.
    """
    os.makedirs("results", exist_ok=True)
    base_name = os.path.splitext(os.path.basename(pdf_path))[0]
    report_path = os.path.join("results", f"{base_name}_report.txt")

    with open(report_path, "w") as f:
        f.write(report_text)

    print(f"\n Report saved to: {report_path}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <pdf_path>")
        sys.exit(1)

    pdf_path = sys.argv[1]
    if not os.path.exists(pdf_path):
        print(f"File not found: {pdf_path}")
        sys.exit(1)

    final_results = run_analysis(pdf_path)

    # Print clean report
    print(final_results["report"])

    # Save to results/ folder
    save_report(final_results["report"], pdf_path)


if __name__ == "__main__":
    main()
