# modules/risk_engine.py

class RiskEngine:
    """
    Module 6: Risk Engine
    Purpose: Assign a risk score based on anomalies, keywords, payloads, and IOCs.
    """

    def __init__(self, results: dict):
        self.results = results

    def run(self) -> dict:
        score = 0
        reasons = []

        # Metadata anomalies
        anomalies = self.results.get("metadata", {}).get("anomalies", [])
        if anomalies:
            score += len(anomalies) * 10
            reasons.extend([f"Metadata anomaly: {a}" for a in anomalies])

        # Keywords
        keywords = self.results.get("keywords", {}).get("keyword_hits", {})
        score += sum(keywords.values()) * 5
        for k, v in keywords.items():
            reasons.append(f"Keyword {k} detected {v} times")

        # Payloads
        payloads = self.results.get("deep_parse", {}).get("extracted_payloads", [])
        score += len(payloads) * 15
        for p in payloads:
            reasons.append(f"Payload type {p.get('type')} extracted")

        # IOCs
        iocs = self.results.get("iocs", {}).get("iocs", {})
        score += sum(len(v) for v in iocs.values()) * 20
        for label, vals in iocs.items():
            reasons.append(f"{label} found: {', '.join(vals)}")

        # Cap score
        score = min(score, 100)

        # Severity
        if score < 30:
            severity = "Low"
        elif score < 60:
            severity = "Medium"
        elif score < 85:
            severity = "High"
        else:
            severity = "Critical"

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }
