#!/usr/bin/env python3
"""
Run compatibility analysis and generate a JSON report.

This script analyzes dependency upgrades for breaking changes and generates
code fixes to maintain compatibility. It's designed to be called from the
Remediation workflow before applying dependency upgrades.

Usage:
    python run_compatibility_analysis.py <findings_json> <manifest_file> <source_dir>

Arguments:
    findings_json: Path to normalized findings JSON file
    manifest_file: Path to dependency manifest (pom.xml, package.json, etc.)
    source_dir: Path to source code directory

Output:
    JSON report with breaking changes and code fixes (printed to stdout)

Example:
    python run_compatibility_analysis.py snyk.json pom.xml src/src/main/java

Requirements: 16.1, 16.2, 16.3, 16.4, 16.5
"""

import sys
import json
import logging
from pathlib import Path

from compatibility_analyzer import CompatibilityAnalyzer
from normalization.models import DependencyChange

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def extract_dependency_changes(findings_data):
    """
    Extract dependency changes from normalized findings.
    
    Args:
        findings_data: Normalized findings JSON data
    
    Returns:
        List of DependencyChange objects
    
    Implementation Notes:
    - Extracts package manager from manifest_file field
    - Handles both old and new normalized schema formats
    - Filters out findings without fix versions
    """
    changes = []
    dependencies = findings_data.get("dependency_vulnerabilities", [])
    
    logger.info(f"Extracting dependency changes from {len(dependencies)} finding(s)")
    
    for dep in dependencies:
        # Extract package manager from manifest file
        manifest = dep.get("manifest_file", "pom.xml")
        if "pom.xml" in manifest.lower():
            package_manager = "maven"
        elif "package.json" in manifest.lower():
            package_manager = "npm"
        elif "requirements.txt" in manifest.lower() or "pyproject.toml" in manifest.lower():
            package_manager = "pip"
        elif "build.gradle" in manifest.lower():
            package_manager = "gradle"
        else:
            package_manager = "unknown"
            logger.warning(f"Unknown package manager for manifest: {manifest}")
        
        # Extract version information
        current_version = dep.get("current_version", "")
        target_version = dep.get("recommended_fix_version", "")
        
        # Skip if no fix version available
        if not target_version or target_version == "unknown":
            logger.warning(f"Skipping {dep.get('package', 'unknown')}: no fix version available")
            continue
        
        change = DependencyChange(
            package_name=dep.get("package", ""),
            current_version=current_version,
            target_version=target_version,
            package_manager=package_manager
        )
        changes.append(change)
        
        logger.info(
            f"  - {change.package_name}: {change.current_version} → {change.target_version} "
            f"({change.package_manager})"
        )
    
    return changes


def generate_report(dependency_changes, code_fixes):
    """
    Generate a JSON report of compatibility analysis results.
    
    Args:
        dependency_changes: List of DependencyChange objects
        code_fixes: List of CodeFix objects
    
    Returns:
        Dictionary containing the report data
    """
    # Count breaking changes
    breaking_changes_count = len([
        fix for fix in code_fixes
        if "breaking" in fix.reason.lower() or "major version" in fix.reason.lower()
    ])
    
    report = {
        "summary": {
            "total_dependencies": len(dependency_changes),
            "breaking_changes_detected": breaking_changes_count,
            "code_fixes_generated": len(code_fixes)
        },
        "dependency_changes": [
            {
                "package_name": change.package_name,
                "current_version": change.current_version,
                "target_version": change.target_version,
                "package_manager": change.package_manager
            }
            for change in dependency_changes
        ],
        "breaking_changes": breaking_changes_count,
        "code_fixes": [
            {
                "file_path": fix.file_path,
                "reason": fix.reason,
                "original_code_preview": (
                    fix.original_code[:200] + "..."
                    if len(fix.original_code) > 200
                    else fix.original_code
                ),
                "fixed_code_preview": (
                    fix.fixed_code[:200] + "..."
                    if len(fix.fixed_code) > 200
                    else fix.fixed_code
                )
            }
            for fix in code_fixes
        ]
    }
    
    return report


def main():
    """Main entry point for compatibility analysis script."""
    if len(sys.argv) < 4:
        print("Usage: python run_compatibility_analysis.py <findings_json> <manifest_file> <source_dir>")
        print()
        print("Arguments:")
        print("  findings_json: Path to normalized findings JSON file")
        print("  manifest_file: Path to dependency manifest (pom.xml, package.json, etc.)")
        print("  source_dir: Path to source code directory")
        print()
        print("Example:")
        print("  python run_compatibility_analysis.py snyk.json pom.xml src/src/main/java")
        sys.exit(1)
    
    findings_file = sys.argv[1]
    manifest_file = sys.argv[2]
    source_dir = sys.argv[3]
    
    logger.info("=" * 60)
    logger.info("Compatibility Analysis")
    logger.info("=" * 60)
    logger.info(f"Findings file: {findings_file}")
    logger.info(f"Manifest file: {manifest_file}")
    logger.info(f"Source directory: {source_dir}")
    logger.info("")
    
    # Validate input files
    if not Path(findings_file).exists():
        logger.error(f"Findings file not found: {findings_file}")
        sys.exit(1)
    
    if not Path(manifest_file).exists():
        logger.error(f"Manifest file not found: {manifest_file}")
        sys.exit(1)
    
    if not Path(source_dir).exists():
        logger.error(f"Source directory not found: {source_dir}")
        sys.exit(1)
    
    # Load findings
    logger.info("Loading findings...")
    try:
        with open(findings_file) as f:
            findings_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse findings JSON: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load findings: {e}")
        sys.exit(1)
    
    # Extract dependency changes
    logger.info("Extracting dependency changes...")
    dependency_changes = extract_dependency_changes(findings_data)
    
    if not dependency_changes:
        logger.info("No dependency changes found")
        # Output empty report
        report = {
            "summary": {
                "total_dependencies": 0,
                "breaking_changes_detected": 0,
                "code_fixes_generated": 0
            },
            "dependency_changes": [],
            "breaking_changes": 0,
            "code_fixes": []
        }
        print(json.dumps(report, indent=2))
        return
    
    logger.info(f"Found {len(dependency_changes)} dependency change(s)")
    logger.info("")
    
    # Run compatibility analysis
    logger.info("Running compatibility analysis...")
    analyzer = CompatibilityAnalyzer()
    
    try:
        code_fixes = analyzer.analyze(dependency_changes, source_root=source_dir)
    except Exception as e:
        logger.error(f"Compatibility analysis failed: {e}")
        # Output report with error
        report = {
            "summary": {
                "total_dependencies": len(dependency_changes),
                "breaking_changes_detected": 0,
                "code_fixes_generated": 0,
                "error": str(e)
            },
            "dependency_changes": [
                {
                    "package_name": change.package_name,
                    "current_version": change.current_version,
                    "target_version": change.target_version,
                    "package_manager": change.package_manager
                }
                for change in dependency_changes
            ],
            "breaking_changes": 0,
            "code_fixes": []
        }
        print(json.dumps(report, indent=2))
        sys.exit(1)
    
    logger.info(f"Generated {len(code_fixes)} code fix(es)")
    logger.info("")
    
    # Generate report
    logger.info("Generating report...")
    report = generate_report(dependency_changes, code_fixes)
    
    # Log summary
    logger.info("=" * 60)
    logger.info("Analysis Summary")
    logger.info("=" * 60)
    logger.info(f"Total dependencies: {report['summary']['total_dependencies']}")
    logger.info(f"Breaking changes detected: {report['summary']['breaking_changes_detected']}")
    logger.info(f"Code fixes generated: {report['summary']['code_fixes_generated']}")
    logger.info("=" * 60)
    
    # Output JSON report to stdout
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
