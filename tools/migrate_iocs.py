#!/usr/bin/env python3
"""Migrate IoCs.txt to IoCs.json with auto-detection."""

import json
from pathlib import Path


def detect_type(value):
    """Auto-detect IoC type (copy from ioc_scan.py)"""
    # ... (implementation from scanner)


def main():
    input_file = Path(
        "scripts/npm-Supply-Chain-Attack-IoCs-Detection-Remediation/IoCs.txt"
    )
    output_file = Path("IoCs.json")

    iocs = []
    with open(input_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                iocs.append(
                    {
                        "type": detect_type(line),
                        "value": line,
                        "tags": ["npm-supply-chain-2025"],
                        "source": "https://github.com/AdityaBhatt3010/npm-Supply-Chain-Attack-IoCs-Detection-Remediation",
                        "comment": "September 2025 npm supply chain compromise",
                    }
                )

    with open(output_file, "w") as f:
        json.dump(iocs, f, indent=2, sort_keys=True)

    print(f"Migrated {len(iocs)} IoCs to {output_file}")


if __name__ == "__main__":
    main()
