#!/usr/bin/env python3
"""
SIFT Guardian Demo
Analyzes the included sample file to demonstrate capabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.forensics import FileAnalyzer

print("\n" + "="*70)
print("SIFT GUARDIAN - Autonomous Forensic Investigation Agent")
print("="*70)

# Analyze the sample
sample = "evidence/suspicious_sample.py"
print(f"\nAnalyzing: {sample}\n")

analyzer = FileAnalyzer()
result = analyzer.analyze_file(sample)

# Show results
print("FILE ANALYSIS:")
print(f"  SHA-256: {result['hashes']['sha256']}")
print(f"  Size: {result['file_size']:,} bytes")
print(f"  Entropy: {result['entropy']:.2f}")

if result.get('malware_patterns'):
    summary = result['malware_summary']
    print(f"\nMALWARE DETECTION:")
    print(f"  Patterns matched: {summary['total_matches']}")
    print(f"  Risk score: {summary['risk_score']}/100")
    print(f"  Threat level: {summary['max_severity'].upper()}")
    print(f"  Categories: {', '.join(summary['categories'])}")
else:
    print("\n✓ No malware patterns detected")

print("\n" + "="*70)
print("✓ Analysis complete\n")
