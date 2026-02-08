# Needle — PDF Malware Analysis Toolkit

## Overview
Needle is a lightweight command‑line toolkit for **static analysis and triage of PDF files**. It inspects PDF metadata, enumerates embedded objects, scans for suspicious keywords, parses streams and JavaScript snippets, extracts Indicators of Compromise (IOCs), and computes a heuristic risk score. The goal is fast, reproducible triage so analysts can prioritize samples for deeper dynamic analysis.

---

## Features
- **Metadata Extraction** — Read and flag suspicious metadata fields (Author, Creator, Producer, dates).  
- **Object Enumeration** — Count and classify PDF objects, identify embedded files and streams.  
- **Keyword Scanning** — Detect PDF attack keywords such as `/JavaScript`, `/OpenAction`, `/JS`, `/EmbeddedFile`.  
- **Deep Parsing** — Extract and decode compressed/encoded streams and JavaScript snippets for inspection.  
- **IOC Extraction** — Regex‑based discovery of URLs, domains, IPs, file paths, and suspicious strings.  
- **Heuristic Risk Scoring** — Aggregate findings into a configurable risk score and severity label.  
- **Report Generation** — Human‑readable console summary and saved report files in `results/`.  
- **Modular Design** — Each analyzer is a separate module for easy extension and testing.

---

## Quick Workflow
1. **Input:** Provide a PDF file to analyze.  
2. **Analyze:** Run modules (metadata → keywords → objects → deep parse → IOC extraction).  
3. **Evaluate:** Risk Engine aggregates module outputs and computes a score.  
4. **Output:** Report Generator prints a summary and saves a detailed report to `results/`.

---

## Repository Structure
```
needle/
│── README.md
│── main.py
│── .gitignore
│
├── modules/
│   ├── metadata_extractor.py
│   ├── object_enumerator.py
│   ├── keyword_scanner.py
│   ├── deep_parser.py
│   ├── ioc_extractor.py
│   ├── risk_engine.py
│   └── report.py
│
├── data/
│   └── samples/
│       └── sample.pdf
│
└── results/
    └── sample_report.txt
```

---
## Installation

**Clone the repository** :
```
git clone https://github.com/Om-Fulsundar/needle.git

cd needle
```

## Requirements / Libraries
- **Python 3.8+** (recommended)  
- **PyPDF2** — basic PDF parsing and object access    
- **Standard Python libs:** `re`, `hashlib`, `os`, `sys`, `datetime`, `argparse`

Install Python dependencies:
```bash
pip install (requirement)
```

---

## Usage
Place a test PDF in `data/samples/` and run:
```bash
python3 main.py data/samples/sample.pdf
```

Outputs:
- Console summary with risk score and top findings.  
- Detailed report saved to `results/<input_name>_report.txt`.

---

## Example Report Snippet
```
=== Needle PDF Analysis Report ===
File: sample.pdf
Timestamp: 2026-02-09 02:29:00

Metadata:
- Author: unknown
- Producer: ReportLab PDF Library - suspicious

Keywords detected:
- /JavaScript, /OpenAction

Objects:
- EmbeddedFile: 1
- Streams: 12 (2 compressed)

IOCs:
- URL: http://malicious.example.com/payload
- IP: 192.0.2.123

Risk Score: 78
Severity: High
Reasons:
- Embedded JavaScript and OpenAction present
- Suspicious domain found
- Embedded file detected
```

---

## Limitations
- **Static only:** Needle does not execute JavaScript or emulate PDF viewer behavior; dynamic behavior may be missed.  
- **Encrypted PDFs:** Password‑protected or encrypted PDFs cannot be analyzed without the password.  
- **Heuristic scoring:** Risk scores are for triage and should not be treated as definitive verdicts.


## Future Improvements  
- Support HTML/PDF formatted reports and aggregated dashboards.  
- Add YARA rules and optional AV/YARA integration for richer detection.  
- Batch processing and parallel analysis for large corpora.

---

## Contact
Author: **Om Fulsundar**  
Repository: *https://github.com/Om-Fulsundar/needle.git*



