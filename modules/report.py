# modules/report.py

def generate_report(results: dict) -> str:
    """
    Generates a clean, professional PDF malware analysis report.
    Input: results dictionary from main.py
    Output: formatted string report
    """

    lines = []
    lines.append("=== PDF Malware Analysis Report ===\n")

    # Metadata (beautified with spacing)
    meta = results.get("metadata", {})
    lines.append(">> Metadata")
    if meta:
        for k, v in meta.items():
            lines.append(f"{k}:")
            lines.append(f"    {v}\n")   # indent + extra spacing
    else:
        lines.append("No metadata extracted.\n")

    # Metadata anomalies (if present)
    anomalies = results.get("risk", {}).get("reasons", [])
    meta_anomalies = [r for r in anomalies if "Metadata anomaly" in r]
    if meta_anomalies:
        lines.append(">> Metadata Anomalies")
        for a in meta_anomalies:
            lines.append(f"- {a}")
        lines.append("")

    # Embedded Objects
    obj = results.get("objects", {})
    lines.append(">> Embedded Objects")
    lines.append(f"Total objects: {obj.get('total_objects', 0)}")
    if obj.get("object_types"):
        lines.append("Types:")
        for t in obj["object_types"]:
            lines.append(f"- {t}")
    lines.append("")

    # Suspicious Keywords
    kw = results.get("keywords", {})
    lines.append(">> Suspicious Keywords")
    lines.append(f"Total keywords: {kw.get('total_keywords', 0)}")
    if kw.get("keywords"):
        lines.append("Keywords:")
        for k in kw["keywords"]:
            lines.append(f"- {k}")
    lines.append("")

    # Embedded Payloads
    dp = results.get("deep_parse", {})
    lines.append(">> Embedded Payloads")
    lines.append(f"Total payloads: {dp.get('total_payloads', 0)}")
    if dp.get("extracted_payloads"):
        lines.append("Payload snippets:")
        for p in dp["extracted_payloads"][:5]:  # show first 5
            snippet = p.get("snippet", "").strip()
            if snippet:
                lines.append(f"- {snippet[:100]}...")  # truncate long ones
    lines.append("")

    # IOCs
    ioc = results.get("iocs", {})
    lines.append(">> Indicators of Compromise (IOCs)")
    lines.append(f"Total IOCs: {ioc.get('total_iocs', 0)}")
    for label, items in ioc.get("iocs", {}).items():
        lines.append(f"{label.capitalize()}:")
        for i in items[:10]:  # show first 10
            lines.append(f"- {i}")
    lines.append("")

    # Risk Assessment
    risk = results.get("risk", {})
    lines.append(">> Risk Assessment")
    lines.append(f"Risk Score: {risk.get('risk_score', 'N/A')}")
    lines.append(f"Severity Level: {risk.get('severity', 'Unknown')}")
    if risk.get("reasons"):
        lines.append("Reasons:")
        for r in risk["reasons"]:
            lines.append(f"- {r}")
    lines.append("")

    lines.append("=== End of Report ===")
    return "\n".join(lines)
