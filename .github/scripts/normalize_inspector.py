#!/usr/bin/env python3
"""
Normalize AWS Inspector findings using the normalization framework.

This script processes AWS Inspector JSON findings and normalizes them to the
common vulnerability schema used by the remediation pipeline. It filters findings
to application dependencies only (npm, Maven, Gradle, pip) and excludes OS-level
packages.

Usage:
    python normalize_inspector.py --input inspector.json --output normalized.json

Design: This script serves as the entry point for Inspector normalization in the
GitHub Actions workflow. It uses the InspectorAdapter to parse findings and the
DeduplicationService to remove duplicates.

Architecture Decision Record (ADR-002): Application Dependency Filtering
This script implements filtering at the adapter level, ensuring only application
dependencies reach the remediation pipeline.
"""

import argparse
import json
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from normalization.framework import NormalizationFramework
from normalization.adapters.inspector_adapter import InspectorAdapter
from deduplication import DeduplicationService


def load_inspector_findings(file_path: str) -> dict:
    """
    Load AWS Inspector findings from JSON file.
    
    Args:
        file_path: Path to Inspector JSON file
    
    Returns:
        Inspector findings dictionary
    
    Raises:
        FileNotFoundError: If file does not exist
        json.JSONDecodeError: If file is not valid JSON
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Inspector JSON file not found: {file_path}")
    
    with open(file_path, "r") as f:
        data = json.load(f)
    
    return data


def build_output_format(findings: list, scanner: str = "inspector") -> dict:
    """
    Build output in the format expected by create_jira.py and remediation scripts.
    
    This format matches the existing Snyk normalization output format to ensure
    backward compatibility with the remediation pipeline.
    
    Args:
        findings: List of NormalizedFinding objects
        scanner: Scanner name (default: "inspector")
    
    Returns:
        Dictionary in the normalized output format
    """
    # Separate findings by remediation type
    dependency_vulns = []
    code_vulns = []
    
    for finding in findings:
        finding_dict = finding.to_dict()
        
        if finding.remediation_type == "dependency":
            dependency_vulns.append(finding_dict)
        elif finding.remediation_type == "code":
            code_vulns.append(finding_dict)
    
    # Build output matching the format from normalize.py
    output = {
        "scan_metadata": {
            "scanner": scanner,
            "project": os.environ.get("GITHUB_REPOSITORY", "unknown").split("/")[-1],
            "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "branch": os.environ.get("GITHUB_REF_NAME", "main"),
            "commit": os.environ.get("GITHUB_SHA", "unknown"),
            "scan_time": datetime.utcnow().isoformat(),
            "findings_count": len(findings)
        },
        "dependency_vulnerabilities": dependency_vulns,
        "code_vulnerabilities": code_vulns
    }
    
    return output


def main():
    """
    Main entry point for Inspector normalization.
    
    Process:
    1. Parse command-line arguments
    2. Load Inspector JSON findings
    3. Initialize normalization framework with Inspector adapter
    4. Normalize findings (includes filtering to application dependencies)
    5. Deduplicate findings (remove internal duplicates)
    6. Write normalized output in format compatible with remediation pipeline
    """
    parser = argparse.ArgumentParser(
        description="Normalize AWS Inspector findings to common vulnerability schema"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to AWS Inspector JSON findings file"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output normalized JSON file"
    )
    args = parser.parse_args()
    
    try:
        # Load Inspector findings
        print(f"Loading Inspector findings from: {args.input}")
        inspector_data = load_inspector_findings(args.input)
        
        # Count raw findings
        raw_count = len(inspector_data.get("findings", []))
        print(f"Raw Inspector findings: {raw_count}")
        
        # Initialize normalization framework
        framework = NormalizationFramework()
        framework.register_adapter("inspector", InspectorAdapter())
        
        # Normalize findings (includes application dependency filtering)
        print("Normalizing findings...")
        normalized_findings = framework.normalize("inspector", inspector_data)
        
        print(f"Normalized findings (after filtering): {len(normalized_findings)}")
        
        # Count filtered findings
        filtered_count = raw_count - len(normalized_findings)
        if filtered_count > 0:
            print(f"Filtered out {filtered_count} OS-level or infrastructure findings")
        
        # Deduplicate (in case Inspector has internal duplicates)
        print("Deduplicating findings...")
        dedup_service = DeduplicationService()
        deduplicated = dedup_service.deduplicate(normalized_findings)
        
        duplicate_count = len(normalized_findings) - len(deduplicated)
        if duplicate_count > 0:
            print(f"Removed {duplicate_count} duplicate findings")
        
        print(f"Final unique findings: {len(deduplicated)}")
        
        # Build output in format compatible with remediation pipeline
        output = build_output_format(deduplicated, scanner="inspector")
        
        # Write output
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Normalized findings written to: {args.output}")
        
        # Print summary
        dep_count = len(output["dependency_vulnerabilities"])
        code_count = len(output["code_vulnerabilities"])
        print(f"\nSummary:")
        print(f"  - Dependency vulnerabilities: {dep_count}")
        print(f"  - Code vulnerabilities: {code_count}")
        print(f"  - Total: {dep_count + code_count}")
        
        return 0
        
    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
