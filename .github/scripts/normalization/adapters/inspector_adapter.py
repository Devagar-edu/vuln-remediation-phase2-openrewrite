"""
AWS Inspector Scanner Adapter

This module implements the scanner adapter for AWS Inspector vulnerability findings.
It parses Inspector JSON output and filters to application dependencies only.

Design: This adapter implements application dependency filtering as a core
responsibility, excluding OS-level packages before normalization. It focuses
exclusively on application dependencies (npm, Maven, Gradle, pip) that can be
fixed via package manager updates.

Architecture Decision Record (ADR-002): Application Dependency Filtering
- Decision: Filter Inspector findings to application dependencies only
- Rationale: OS-level vulnerabilities require different remediation strategies
  (infrastructure updates, container base image changes) that are outside the
  scope of application code remediation
- Consequences: Some Inspector findings will be excluded; separate workflows
  may be needed for infrastructure vulnerabilities

Filtering Rationale: OS-level vulnerabilities (apt, yum, apk, rpm) require
infrastructure remediation (base image updates, OS patches) rather than
application code changes. This adapter focuses exclusively on application
dependencies that can be fixed via package manager updates.
"""

import json
import uuid
import re
from typing import List, Dict, Any, Optional

from .base import ScannerAdapter
from ..models import NormalizedFinding


class InspectorAdapter(ScannerAdapter):
    """
    Adapter for AWS Inspector vulnerability scanner.
    
    This adapter parses AWS Inspector JSON findings and filters to application
    dependencies only. It excludes OS-level packages (apt, yum, apk, rpm) and
    focuses on application package managers (npm, Maven, Gradle, pip).
    
    Inspector Output Format:
    - JSON with "findings" array
    - Each finding contains packageVulnerabilityDetails with vulnerable packages
    - Package manager is specified in vulnerablePackages[].packageManager field
    
    Implementation Strategy:
    - Parse Inspector JSON format (findings array structure)
    - Apply application dependency filtering (npm, Maven, Gradle, pip only)
    - Extract CVE, severity, and fix version information
    - Map Inspector severity levels to normalized levels
    """
    
    # Application package managers we support (Requirement 5.1)
    APP_PACKAGE_MANAGERS = {"npm", "maven", "gradle", "pip", "pypi", "java"}
    
    # OS package managers we exclude (Requirement 5.2)
    OS_PACKAGE_MANAGERS = {"apt", "yum", "apk", "rpm", "dpkg"}
    
    def __init__(self):
        """Initialize the Inspector adapter."""
        self._scanner_name = "inspector"
        self._scanner_version = "1.0.0"
    
    def parse(self, raw_findings: dict) -> List[NormalizedFinding]:
        """
        Parse AWS Inspector JSON output into normalized findings.
        
        This method implements the main parsing logic:
        1. Iterate through findings array
        2. Filter to application dependencies only
        3. Normalize each finding to common schema
        4. Return list of normalized findings
        
        Args:
            raw_findings: Inspector JSON output with "findings" array
        
        Returns:
            List of normalized findings (application dependencies only)
        
        Implementation Note: This method satisfies Requirements 4.1-4.4 by
        parsing Inspector format and filtering to application dependencies.
        """
        findings = []
        
        for raw_finding in raw_findings.get("findings", []):
            # Filter to application dependencies only (Requirement 5)
            if self._is_application_dependency(raw_finding):
                normalized = self._normalize_finding(raw_finding)
                if normalized:
                    findings.append(normalized)
        
        return findings
    
    def _is_application_dependency(self, finding: dict) -> bool:
        """
        Filter to application dependencies only.
        
        This method implements Requirement 5: Application Dependency Scope Filtering.
        It returns True if the finding targets an application dependency
        (npm, Maven, Gradle, pip), False for OS packages or infrastructure.
        
        Filtering Logic (Requirements 5.1-5.6):
        1. Check packageVulnerabilityDetails.vulnerablePackages[].packageManager
        2. Include if packageManager is in APP_PACKAGE_MANAGERS
        3. Exclude if packageManager is in OS_PACKAGE_MANAGERS
        4. Exclude if source is "OS" or "OPERATING_SYSTEM"
        5. Default: exclude if uncertain (fail-safe)
        
        Args:
            finding: Inspector finding dictionary
        
        Returns:
            True if application dependency, False otherwise
        """
        pkg_details = finding.get("packageVulnerabilityDetails", {})
        
        # Check package manager field for each vulnerable package
        for vuln_pkg in pkg_details.get("vulnerablePackages", []):
            pkg_mgr = vuln_pkg.get("packageManager", "").lower()
            
            # Include if application package manager (Requirement 5.1)
            if pkg_mgr in self.APP_PACKAGE_MANAGERS:
                return True
            
            # Exclude if OS package manager (Requirement 5.2)
            if pkg_mgr in self.OS_PACKAGE_MANAGERS:
                return False
        
        # Check source field (Requirement 5.3)
        source = pkg_details.get("source", "").upper()
        if source in ("OS", "OPERATING_SYSTEM", "SYSTEM"):
            return False
        
        # Default: exclude if uncertain (fail-safe, Requirement 5.6)
        return False
    
    def _normalize_finding(self, finding: dict) -> Optional[NormalizedFinding]:
        """
        Convert Inspector finding to normalized format.
        
        This method implements Requirement 4.3: Inspector finding normalization.
        It maps Inspector fields to the normalized schema:
        - findingArn -> id
        - severity -> severity (mapped to normalized levels)
        - packageVulnerabilityDetails.vulnerablePackages -> package info
        - packageVulnerabilityDetails.relatedVulnerabilities -> CVE list
        - remediation.recommendation.text -> fixed_version extraction
        
        Args:
            finding: Inspector finding dictionary
        
        Returns:
            NormalizedFinding object or None if parsing fails
        """
        pkg_details = finding.get("packageVulnerabilityDetails", {})
        vuln_packages = pkg_details.get("vulnerablePackages", [])
        
        if not vuln_packages:
            return None
        
        # Use first vulnerable package (Inspector may list multiple)
        vuln_pkg = vuln_packages[0]
        
        # Extract CVE from vulnerabilityId field (Requirement 5.5)
        cve_list = self._extract_cves(pkg_details)
        
        # Extract fixed version (Requirement 4.4, 5.4)
        fixed_version = self._extract_fixed_version(finding)
        
        # Map severity (Requirement 5.3)
        severity = self._map_severity(finding.get("severity", "MEDIUM"))
        
        # Determine remediation type (Requirement 5.6)
        remediation_type = self._determine_remediation_type(finding)
        
        # Extract repository from resources
        repository = "unknown"
        resources = finding.get("resources", [])
        if resources:
            resource_id = resources[0].get("id", "unknown")
            # Extract repository name from ECR ARN
            if "ecr" in resource_id and "repository" in resource_id:
                # Format: arn:aws:ecr:region:account:repository/name/sha256:hash
                parts = resource_id.split("/")
                if len(parts) >= 2:
                    repository = parts[1]
        
        return NormalizedFinding(
            id=finding.get("findingArn", str(uuid.uuid4())),
            scanner=self._scanner_name,
            package_manager=vuln_pkg.get("packageManager", "unknown").lower(),
            package_name=vuln_pkg.get("name", "unknown"),
            current_version=vuln_pkg.get("version", "unknown"),
            fixed_version=fixed_version,
            severity=severity,
            cve=cve_list,
            manifest_file=self._infer_manifest_file(vuln_pkg.get("packageManager", "unknown")),
            remediation_type=remediation_type,
            repository=repository,
            branch="main",
            commit_id="unknown",
            metadata={
                "inspector_finding_arn": finding.get("findingArn"),
                "inspector_title": finding.get("title"),
                "inspector_description": finding.get("description"),
                "inspector_first_observed": finding.get("firstObservedAt"),
                "inspector_last_observed": finding.get("lastObservedAt"),
                "inspector_exploit_available": finding.get("exploitAvailable"),
                "inspector_fix_available": finding.get("fixAvailable"),
                "inspector_epss_score": finding.get("epss", {}).get("score"),
                "inspector_cvss": pkg_details.get("cvss", []),
                "inspector_reference_urls": pkg_details.get("referenceUrls", []),
                "inspector_file_path": vuln_pkg.get("filePath")
            }
        )
    
    def _extract_fixed_version(self, finding: dict) -> str:
        """
        Extract fixed version from Inspector remediation recommendation.
        
        This method implements Requirement 4.4: fixed version extraction.
        Inspector provides fix information in:
        - packageVulnerabilityDetails.vulnerablePackages[].fixedInVersion
        - remediation.recommendation.text (e.g., "Upgrade to version 2.3.1")
        
        Strategy:
        1. Check fixedInVersion field (most reliable)
        2. Parse remediation text for version pattern
        3. Return "unknown" if no version found
        
        Args:
            finding: Inspector finding dictionary
        
        Returns:
            Fixed version string or "unknown"
        """
        # Strategy 1: Check fixedInVersion field
        pkg_details = finding.get("packageVulnerabilityDetails", {})
        for vuln_pkg in pkg_details.get("vulnerablePackages", []):
            fixed = vuln_pkg.get("fixedInVersion")
            if fixed:
                return fixed
        
        # Strategy 2: Parse remediation text
        remediation = finding.get("remediation", {}).get("recommendation", {}).get("text", "")
        # Match version patterns like "2.3.1", "1.0.0", "9.0.117"
        version_match = re.search(r"version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", remediation, re.IGNORECASE)
        if version_match:
            return version_match.group(1)
        
        return "unknown"
    
    def _extract_cves(self, pkg_details: dict) -> List[str]:
        """
        Extract CVE identifiers from Inspector finding.
        
        This method implements Requirement 5.5: CVE extraction from vulnerabilityId.
        Inspector provides CVE in:
        - packageVulnerabilityDetails.vulnerabilityId (primary)
        - packageVulnerabilityDetails.relatedVulnerabilities[].id
        
        Args:
            pkg_details: packageVulnerabilityDetails dictionary
        
        Returns:
            List of CVE identifiers
        """
        cves = []
        
        # Extract from vulnerabilityId field (primary source)
        vuln_id = pkg_details.get("vulnerabilityId", "")
        if vuln_id and vuln_id.startswith("CVE-"):
            cves.append(vuln_id)
        
        # Extract from relatedVulnerabilities (additional CVEs)
        for vuln in pkg_details.get("relatedVulnerabilities", []):
            cve_id = vuln.get("id", "")
            if cve_id and cve_id.startswith("CVE-"):
                cves.append(cve_id)
        
        return list(set(cves))  # Deduplicate
    
    def _map_severity(self, inspector_severity: str) -> str:
        """
        Map Inspector severity to normalized severity.
        
        This method implements Requirement 5.3: severity mapping.
        Inspector levels: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
        Normalized levels: critical, high, medium, low
        
        Mapping:
        - CRITICAL -> critical
        - HIGH -> high
        - MEDIUM -> medium
        - LOW -> low
        - INFORMATIONAL -> low
        - UNTRIAGED -> medium (default)
        
        Args:
            inspector_severity: Inspector severity string
        
        Returns:
            Normalized severity string (critical, high, medium, low)
        """
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFORMATIONAL": "low",
            "UNTRIAGED": "medium",
        }
        return mapping.get(inspector_severity.upper(), "medium")
    
    def _determine_remediation_type(self, finding: dict) -> str:
        """
        Determine remediation type (dependency or code).
        
        This method implements Requirement 5.6: remediation type determination.
        Inspector findings are primarily dependency vulnerabilities.
        Code vulnerabilities would come from Inspector code scanning (if enabled).
        
        Logic:
        - PACKAGE_VULNERABILITY -> dependency
        - CODE_VULNERABILITY -> code
        - Default -> dependency (most Inspector findings are package vulnerabilities)
        
        Args:
            finding: Inspector finding dictionary
        
        Returns:
            Remediation type string ("dependency" or "code")
        """
        finding_type = finding.get("type", "")
        
        if "PACKAGE_VULNERABILITY" in finding_type:
            return "dependency"
        elif "CODE_VULNERABILITY" in finding_type:
            return "code"
        
        return "dependency"  # Default for Inspector
    
    def _infer_manifest_file(self, package_manager: str) -> str:
        """
        Infer manifest file from package manager.
        
        This helper method maps package managers to their manifest files:
        - maven/java -> pom.xml
        - gradle -> build.gradle
        - npm -> package.json
        - pip/pypi -> requirements.txt
        
        Args:
            package_manager: Package manager name
        
        Returns:
            Manifest file path
        """
        pkg_mgr = package_manager.lower()
        
        manifest_map = {
            "maven": "pom.xml",
            "java": "pom.xml",
            "gradle": "build.gradle",
            "npm": "package.json",
            "pip": "requirements.txt",
            "pypi": "requirements.txt"
        }
        
        return manifest_map.get(pkg_mgr, "unknown")
    
    def get_scanner_name(self) -> str:
        """
        Return the unique identifier for this scanner.
        
        Returns:
            Scanner name: "inspector"
        """
        return self._scanner_name
    
    def get_scanner_version(self) -> str:
        """
        Return the scanner version for audit trail.
        
        Returns:
            Scanner version string
        """
        return self._scanner_version
