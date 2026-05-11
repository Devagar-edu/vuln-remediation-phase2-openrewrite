"""
Snyk Scanner Adapter

This module implements the scanner adapter for Snyk vulnerability findings.
It refactors the existing normalize.py logic into the pluggable adapter pattern.

Design: This adapter encapsulates all Snyk-specific parsing logic, including
dependency vulnerability parsing and code vulnerability parsing. It preserves
100% backward compatibility with the existing normalize.py implementation.

Architecture Decision Record (ADR-004): Backward Compatibility Requirement
- Decision: Existing Snyk workflow must produce identical outputs after refactoring
- Rationale: Minimize risk and deployment complexity; allow gradual rollout
- Consequences: Refactoring must preserve all existing logic exactly
"""

import json
import uuid
import re
from typing import List, Dict, Any, Optional
from packaging import version

from .base import ScannerAdapter
from ..models import NormalizedFinding


class SnykAdapter(ScannerAdapter):
    """
    Adapter for Snyk vulnerability scanner.
    
    This adapter parses both Snyk dependency scan results and Snyk code scan
    results, converting them to the normalized finding format.
    
    Snyk Output Formats:
    - Dependency scans: JSON with "vulnerabilities" array
    - Code scans: SARIF format with "runs" array
    
    Implementation: Refactored from existing normalize.py script to maintain
    100% backward compatibility while following the adapter pattern.
    """
    
    def __init__(self):
        """Initialize the Snyk adapter."""
        self._scanner_name = "snyk"
        self._scanner_version = "1.0.0"
    
    def parse(self, raw_findings: dict) -> List[NormalizedFinding]:
        """
        Parse Snyk JSON output into normalized findings.
        
        This method handles both dependency vulnerabilities and code vulnerabilities
        from Snyk scans. It combines the logic from parse_dependency_scan() and
        parse_code_scan() in the original normalize.py.
        
        Args:
            raw_findings: Snyk JSON output (may contain "vulnerabilities" for
                         dependency scans or "runs" for code scans)
        
        Returns:
            List of normalized findings
        
        Implementation Note: This preserves the exact logic from the original
        normalize.py to ensure backward compatibility.
        """
        findings = []
        
        # Parse dependency vulnerabilities if present
        if "vulnerabilities" in raw_findings:
            findings.extend(self._parse_dependency_vulnerabilities(raw_findings))
        
        # Parse code vulnerabilities if present (SARIF format)
        if "runs" in raw_findings:
            findings.extend(self._parse_code_vulnerabilities(raw_findings))
        
        return findings
    
    def _parse_dependency_vulnerabilities(self, data: dict) -> List[NormalizedFinding]:
        """
        Parse Snyk dependency vulnerabilities.
        
        This method refactors the logic from normalize.py:parse_dependency_scan()
        into the adapter pattern. It preserves all existing logic including:
        - Version extraction using extract_version()
        - Fix version selection from multiple sources
        - Vulnerability grouping by package
        - Version comparison for selecting highest fix version
        
        Args:
            data: Snyk dependency scan JSON
        
        Returns:
            List of normalized findings for dependency vulnerabilities
        """
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Group vulnerabilities by package (same as original normalize.py)
        dep_map = {}
        
        for vuln in vulnerabilities:
            pkg = vuln["packageName"]
            current_version = vuln["version"]
            
            # Extract fix version from multiple possible sources
            fix_version = "unknown"
            if vuln.get("upgradePath"):
                fix_version = vuln["upgradePath"][-1]
            elif vuln.get("nearestFixedInVersion"):
                fix_version = vuln["nearestFixedInVersion"]
            elif vuln.get("patched_versions"):
                fix_version = vuln["patched_versions"]
            elif vuln.get("fixedIn"):
                fix_version = vuln["fixedIn"][0]
            
            # Extract version using existing logic
            fix_ver = self._extract_version(fix_version)
            
            # Group by package
            if pkg not in dep_map:
                dep_map[pkg] = {
                    "id": str(uuid.uuid4()),
                    "package": pkg,
                    "current_version": current_version,
                    "recommended_fix_version": fix_ver,
                    "vulnerabilities": []
                }
            else:
                # Select highest fix version
                existing = dep_map[pkg]["recommended_fix_version"]
                existing_ver = self._extract_version(existing)
                
                if version.parse(fix_ver) > version.parse(existing_ver):
                    dep_map[pkg]["recommended_fix_version"] = fix_ver
            
            # Add vulnerability details
            dep_map[pkg]["vulnerabilities"].append({
                "id": vuln["id"],
                "title": vuln["title"],
                "severity": vuln["severity"],
                "cvss": vuln.get("cvssScore"),
                "cve": vuln.get("identifiers", {}).get("CVE", []),
                "cwe": vuln.get("identifiers", {}).get("CWE", []),
                "exploit": vuln.get("exploit"),
                "description": vuln["description"]
            })
        
        # Convert to normalized findings
        findings = []
        for pkg_data in dep_map.values():
            # Extract CVEs from all vulnerabilities for this package
            all_cves = []
            for vuln in pkg_data["vulnerabilities"]:
                all_cves.extend(vuln.get("cve", []))
            
            # Use highest severity from all vulnerabilities
            severities = [v["severity"] for v in pkg_data["vulnerabilities"]]
            highest_severity = self._select_highest_severity(severities)
            
            finding = NormalizedFinding(
                id=pkg_data["id"],
                scanner=self._scanner_name,
                package_manager=self._infer_package_manager(pkg_data["package"]),
                package_name=pkg_data["package"],
                current_version=pkg_data["current_version"],
                fixed_version=pkg_data["recommended_fix_version"],
                severity=highest_severity.lower(),
                cve=list(set(all_cves)),  # Deduplicate CVEs
                manifest_file=self._infer_manifest_file(pkg_data["package"]),
                remediation_type="dependency",
                repository="demo-repo",  # Default from original normalize.py
                branch="main",
                commit_id="unknown",
                metadata={
                    "snyk_vulnerabilities": pkg_data["vulnerabilities"],
                    "snyk_package": pkg_data["package"],
                    "snyk_current_version": pkg_data["current_version"]
                }
            )
            findings.append(finding)
        
        return findings
    
    def _parse_code_vulnerabilities(self, data: dict) -> List[NormalizedFinding]:
        """
        Parse Snyk code vulnerabilities (SARIF format).
        
        This method refactors the logic from normalize.py:parse_code_scan()
        into the adapter pattern. It preserves all existing logic including:
        - SARIF format parsing
        - Rule mapping
        - Occurrence grouping by rule ID
        
        Args:
            data: Snyk code scan JSON (SARIF format)
        
        Returns:
            List of normalized findings for code vulnerabilities
        """
        code_map = {}
        runs = data.get("runs", [])
        
        for run in runs:
            rules = run["tool"]["driver"]["rules"]
            rule_map = {i: r for i, r in enumerate(rules)}
            
            for result in run.get("results", []):
                rule_index = result["ruleIndex"]
                rule = rule_map[rule_index]
                
                location = result["locations"][0]["physicalLocation"]
                rule_id = result["ruleId"]
                
                occurrence = {
                    "file": location["artifactLocation"]["uri"],
                    "line": location["region"]["startLine"]
                }
                
                # Group by rule ID
                if rule_id not in code_map:
                    code_map[rule_id] = {
                        "id": str(uuid.uuid4()),
                        "rule_id": rule_id,
                        "rule_name": rule["name"],
                        "severity": result.get("level", "medium"),
                        "description": rule["shortDescription"]["text"],
                        "cwe": rule["properties"].get("cwe", []),
                        "tags": rule["properties"].get("tags", []),
                        "occurrences": []
                    }
                
                code_map[rule_id]["occurrences"].append(occurrence)
        
        # Convert to normalized findings
        findings = []
        for code_data in code_map.values():
            # Extract CVEs from CWE if available
            cves = self._extract_cves_from_cwe(code_data.get("cwe", []))
            
            # Map SARIF severity levels to normalized levels
            severity_map = {
                "error": "high",
                "warning": "medium",
                "note": "low"
            }
            normalized_severity = severity_map.get(
                code_data["severity"].lower(), 
                "medium"
            )
            
            finding = NormalizedFinding(
                id=code_data["id"],
                scanner=self._scanner_name,
                package_manager="code",  # Special value for code vulnerabilities
                package_name=code_data["rule_id"],
                current_version="N/A",
                fixed_version="N/A",
                severity=normalized_severity,
                cve=cves,
                manifest_file=code_data["occurrences"][0]["file"] if code_data["occurrences"] else "unknown",
                remediation_type="code",
                repository="demo-repo",  # Default from original normalize.py
                branch="main",
                commit_id="unknown",
                metadata={
                    "snyk_rule_id": code_data["rule_id"],
                    "snyk_rule_name": code_data["rule_name"],
                    "snyk_description": code_data["description"],
                    "snyk_cwe": code_data["cwe"],
                    "snyk_tags": code_data["tags"],
                    "snyk_occurrences": code_data["occurrences"]
                }
            )
            findings.append(finding)
        
        return findings
    
    def _extract_version(self, dep_string: str) -> str:
        """
        Extract version number from dependency string.
        
        This method preserves the exact logic from normalize.py:extract_version()
        to ensure backward compatibility.
        
        Args:
            dep_string: Dependency string that may contain version
        
        Returns:
            Extracted version string or "0" if no version found
        """
        if "@" in dep_string:
            dep_string = dep_string.split("@")[-1]
        
        # Remove common version suffixes
        dep_string = re.sub(
            r'(\.RELEASE|\.FINAL|\.GA|\.SP\d+)', 
            '', 
            dep_string, 
            flags=re.IGNORECASE
        )
        dep_string = re.sub(r'[^0-9\.].*', '', dep_string)
        
        return dep_string.strip() if dep_string else "0"
    
    def _select_highest_severity(self, severities: List[str]) -> str:
        """
        Select the highest severity from a list of severities.
        
        Args:
            severities: List of severity strings
        
        Returns:
            Highest severity string
        """
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }
        
        if not severities:
            return "medium"
        
        return max(severities, key=lambda s: severity_order.get(s.lower(), 0))
    
    def _infer_package_manager(self, package_name: str) -> str:
        """
        Infer package manager from package name format.
        
        Args:
            package_name: Package name
        
        Returns:
            Package manager name (npm, maven, pip, etc.)
        """
        # Maven packages typically have groupId:artifactId format
        if ":" in package_name and "." in package_name.split(":")[0]:
            return "maven"
        
        # Python packages are typically lowercase with hyphens or underscores
        if "-" in package_name or "_" in package_name:
            return "pip"
        
        # Default to npm for JavaScript packages
        return "npm"
    
    def _infer_manifest_file(self, package_name: str) -> str:
        """
        Infer manifest file from package name format.
        
        Args:
            package_name: Package name
        
        Returns:
            Manifest file path
        """
        pkg_mgr = self._infer_package_manager(package_name)
        
        manifest_map = {
            "maven": "pom.xml",
            "pip": "requirements.txt",
            "npm": "package.json"
        }
        
        return manifest_map.get(pkg_mgr, "unknown")
    
    def _extract_cves_from_cwe(self, cwe_list: List[str]) -> List[str]:
        """
        Extract CVE identifiers from CWE list if any are present.
        
        Args:
            cwe_list: List of CWE identifiers
        
        Returns:
            List of CVE identifiers (empty if none found)
        """
        cves = []
        for item in cwe_list:
            if isinstance(item, str) and item.startswith("CVE-"):
                cves.append(item)
        return cves
    
    def get_scanner_name(self) -> str:
        """
        Return the unique identifier for this scanner.
        
        Returns:
            Scanner name: "snyk"
        """
        return self._scanner_name
    
    def get_scanner_version(self) -> str:
        """
        Return the scanner version for audit trail.
        
        Returns:
            Scanner version string
        """
        return self._scanner_version
