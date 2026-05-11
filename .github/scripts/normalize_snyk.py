"""
Snyk Normalization Script

This script normalizes Snyk vulnerability scan results using the new normalization
framework. It replaces the old normalize.py script while maintaining backward
compatibility with the existing Snyk workflow.

Usage:
    python normalize_snyk.py --deps <deps_file> --code <code_file> --output <output_file>

Example:
    python normalize_snyk.py --deps snyk-deps.json --code snyk-code.json --output vuln_report.json
"""

import json
import argparse
import logging
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from normalization.framework import NormalizationFramework
from normalization.adapters.snyk_adapter import SnykAdapter
from deduplication import DeduplicationService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def safe_input_path(user_input):
    """Sanitize input file path using basename strategy."""
    base_dir = os.getcwd()
    filename = os.path.basename(user_input)
    return os.path.join(base_dir, filename)


def safe_output_path(user_input):
    """Sanitize output file path using basename strategy."""
    base_dir = os.getcwd()
    filename = os.path.basename(user_input)
    return os.path.join(base_dir, filename)


def load_json_file(file_path: str) -> dict:
    """
    Load JSON file with error handling.
    
    Args:
        file_path: Path to JSON file
    
    Returns:
        Parsed JSON data
    
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in file {file_path}: {e}")
        raise


def build_summary(findings: list) -> dict:
    """
    Build summary statistics from normalized findings.
    
    Args:
        findings: List of normalized findings
    
    Returns:
        Summary dictionary with counts by severity
    """
    summary = {
        "total_findings": len(findings),
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0
    }
    
    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        if severity == "critical":
            summary["critical_count"] += 1
        elif severity == "high":
            summary["high_count"] += 1
        elif severity == "medium":
            summary["medium_count"] += 1
        elif severity == "low":
            summary["low_count"] += 1
    
    # Separate counts by remediation type for backward compatibility
    dep_findings = [f for f in findings if f.get("remediation_type") == "dependency"]
    code_findings = [f for f in findings if f.get("remediation_type") == "code"]
    
    summary["total_dependencies"] = len(dep_findings)
    summary["total_code_issues"] = len(code_findings)
    
    return summary


def convert_to_legacy_format(findings: list) -> dict:
    """
    Convert normalized findings to legacy format for backward compatibility.
    
    This ensures the output format matches the original normalize.py output,
    maintaining compatibility with existing scripts (create_jira.py, fix_dependencies.py).
    
    Args:
        findings: List of NormalizedFinding objects (as dicts)
    
    Returns:
        Dictionary in legacy format with dependency_vulnerabilities and code_vulnerabilities
    """
    dependency_vulns = []
    code_vulns = []
    
    for finding in findings:
        if finding.get("remediation_type") == "dependency":
            # Convert to legacy dependency format
            dep_vuln = {
                "id": finding["id"],
                "package": finding["package_name"],
                "current_version": finding["current_version"],
                "recommended_fix_version": finding["fixed_version"],
                "vulnerabilities": finding.get("metadata", {}).get("snyk_vulnerabilities", [])
            }
            dependency_vulns.append(dep_vuln)
        
        elif finding.get("remediation_type") == "code":
            # Convert to legacy code format
            code_vuln = {
                "id": finding["id"],
                "rule_id": finding.get("metadata", {}).get("snyk_rule_id", ""),
                "rule_name": finding.get("metadata", {}).get("snyk_rule_name", ""),
                "severity": finding["severity"],
                "description": finding.get("metadata", {}).get("snyk_description", ""),
                "cwe": finding.get("metadata", {}).get("snyk_cwe", []),
                "tags": finding.get("metadata", {}).get("snyk_tags", []),
                "occurrences": finding.get("metadata", {}).get("snyk_occurrences", [])
            }
            code_vulns.append(code_vuln)
    
    return {
        "dependency_vulnerabilities": dependency_vulns,
        "code_vulnerabilities": code_vulns
    }


def main():
    """Main entry point for Snyk normalization script."""
    parser = argparse.ArgumentParser(
        description="Normalize Snyk scan results using the normalization framework"
    )
    parser.add_argument(
        "--deps",
        required=True,
        help="Path to Snyk dependency scan JSON file"
    )
    parser.add_argument(
        "--code",
        required=True,
        help="Path to Snyk code scan JSON file"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output normalized JSON file"
    )
    args = parser.parse_args()
    
    # Sanitize all input paths
    deps_path = safe_input_path(args.deps)
    code_path = safe_input_path(args.code)
    output_path = safe_output_path(args.output)
    
    logger.info("Starting Snyk normalization")
    logger.info(f"Dependency scan file: {deps_path}")
    logger.info(f"Code scan file: {code_path}")
    logger.info(f"Output file: {output_path}")
    
    try:
        # Load Snyk scan results
        deps_data = load_json_file(deps_path)
        code_data = load_json_file(code_path)
        
        # Initialize normalization framework
        framework = NormalizationFramework()
        
        # Register Snyk adapter
        snyk_adapter = SnykAdapter()
        framework.register_adapter("snyk", snyk_adapter)
        
        logger.info("Registered Snyk adapter with framework")
        
        # Normalize dependency vulnerabilities
        dep_findings = framework.normalize("snyk", deps_data)
        logger.info(f"Normalized {len(dep_findings)} dependency findings")
        
        # Normalize code vulnerabilities
        code_findings = framework.normalize("snyk", code_data)
        logger.info(f"Normalized {len(code_findings)} code findings")
        
        # Combine all findings
        all_findings = dep_findings + code_findings
        logger.info(f"Total findings: {len(all_findings)}")
        
        # Deduplicate findings (in case there are duplicates within Snyk results)
        dedup_service = DeduplicationService()
        deduplicated_findings = dedup_service.deduplicate(all_findings)
        logger.info(f"After deduplication: {len(deduplicated_findings)} findings")
        
        # Convert to dictionaries for JSON serialization
        findings_dicts = [f.to_dict() for f in deduplicated_findings]
        
        # Build summary
        summary = build_summary(findings_dicts)
        
        # Convert to legacy format for backward compatibility
        legacy_format = convert_to_legacy_format(findings_dicts)
        
        # Build output in format compatible with existing scripts
        output = {
            "scan_metadata": {
                "scanner": "snyk",
                "scan_time": datetime.utcnow().isoformat(),
                "project": "demo-project",
                "repository": "demo-repo",
                "branch": "main",
                "commit_id": "unknown",
                "framework_version": "1.0.0"
            },
            "dependency_vulnerabilities": legacy_format["dependency_vulnerabilities"],
            "code_vulnerabilities": legacy_format["code_vulnerabilities"],
            "summary": summary,
            # Include normalized findings for future use
            "normalized_findings": findings_dicts
        }
        
        # Write output
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        
        logger.info(f"Normalized scan written to: {output_path}")
        logger.info(f"Summary: {summary['total_dependencies']} dependency issues, "
                   f"{summary['total_code_issues']} code issues")
        
        return 0
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
