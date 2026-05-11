"""
Deduplication Service for Vulnerability Findings

This module identifies and merges duplicate vulnerability findings from multiple
scanners (Snyk and Inspector). Deduplication prevents duplicate remediation work
and duplicate Jira tickets.

Design: Uses CVE + package name + version + repository as the deduplication key.
This satisfies Requirements 8.1-8.5 and ADR-003 (CVE-Based Deduplication).

Architecture Decision Record (ADR-003): CVE-Based Deduplication
- Decision: Use CVE + package name + version + repository as the deduplication key
- Rationale: CVE is the most reliable cross-scanner identifier for the same vulnerability
- Consequences: Vulnerabilities without CVEs may not be deduplicated using "NO_CVE"
  placeholder; scanner-specific IDs are preserved in metadata
"""

from typing import List, Dict, Tuple
from collections import defaultdict
from packaging import version
import logging

from normalization.models import NormalizedFinding

logger = logging.getLogger(__name__)


class DeduplicationService:
    """
    Identifies and merges duplicate vulnerability findings from multiple scanners.
    
    Design: Uses CVE as the primary deduplication key because it is the most
    reliable cross-scanner identifier. Scanner-specific IDs are preserved in
    metadata for audit trail.
    
    Deduplication rationale: Multiple scanners may report the same vulnerability
    with different IDs but the same CVE. Merging prevents duplicate remediation
    work and duplicate Jira tickets.
    
    Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 15.4
    """
    
    def deduplicate(self, findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        """
        Deduplicate findings across scanners.
        
        Args:
            findings: List of normalized findings from all scanners
        
        Returns:
            Deduplicated list with merged metadata
        
        Algorithm:
        1. Group findings by (CVE, package_name, current_version, repository)
        2. For each group with multiple findings:
           - Merge scanner sources
           - Select highest severity
           - Select most recent fixed version
           - Preserve all scanner-specific metadata
        3. For single-finding groups, return as-is
        
        Validates: Requirement 8.1 (deduplication key), 8.2 (merge duplicates)
        """
        if not findings:
            return []
        
        groups = self._group_by_key(findings)
        deduplicated = []
        
        duplicate_count = 0
        for key, group in groups.items():
            if len(group) == 1:
                # Single finding, no deduplication needed
                deduplicated.append(group[0])
            else:
                # Multiple findings, merge them
                merged = self._merge_findings(group)
                deduplicated.append(merged)
                duplicate_count += len(group) - 1
        
        if duplicate_count > 0:
            logger.info(
                f"Deduplicated {duplicate_count} duplicate findings. "
                f"Original: {len(findings)}, Deduplicated: {len(deduplicated)}"
            )
        
        return deduplicated
    
    def _group_by_key(
        self, findings: List[NormalizedFinding]
    ) -> Dict[Tuple[str, str, str, str], List[NormalizedFinding]]:
        """
        Group findings by deduplication key.
        
        Deduplication key: (CVE, package_name, current_version, repository)
        
        For findings with multiple CVEs, uses the first CVE.
        For findings with no CVEs, uses "NO_CVE" placeholder.
        
        Args:
            findings: List of normalized findings
        
        Returns:
            Dictionary mapping deduplication keys to lists of findings
        
        Validates: Requirement 8.1 (deduplication key criteria)
        """
        groups = defaultdict(list)
        
        for finding in findings:
            # Use first CVE if multiple exist, "NO_CVE" if none
            cve = finding.cve[0] if finding.cve else "NO_CVE"
            
            # Create deduplication key
            key = (cve, finding.package_name, finding.current_version, finding.repository)
            
            groups[key].append(finding)
        
        return groups
    
    def _merge_findings(self, findings: List[NormalizedFinding]) -> NormalizedFinding:
        """
        Merge multiple findings into one.
        
        Merge strategy:
        - ID: Use first finding's ID
        - Scanner: Combine all scanner names (e.g., "snyk,inspector")
        - Severity: Select highest (critical > high > medium > low)
        - Fixed version: Select most recent version using packaging.version
        - CVE: Union of all CVEs
        - Metadata: Merge all scanner-specific metadata
        - Add deduplicated_from and source_scanners to metadata
        
        Args:
            findings: List of duplicate findings to merge
        
        Returns:
            Single merged finding
        
        Validates: Requirements 8.2 (merge duplicates), 8.3 (preserve sources),
                   8.4 (highest severity), 8.5 (most recent fix version)
        """
        if not findings:
            raise ValueError("Cannot merge empty list of findings")
        
        if len(findings) == 1:
            return findings[0]
        
        base = findings[0]
        
        # Combine scanner names (comma-separated, sorted, deduplicated)
        # Validates: Requirement 8.3 (preserve source scanner information)
        scanner_names = set()
        for f in findings:
            # Handle already-merged findings (scanner field may contain commas)
            scanner_names.update(s.strip() for s in f.scanner.split(','))
        scanners = ",".join(sorted(scanner_names))
        
        # Select highest severity
        # Validates: Requirement 8.4 (select highest severity)
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        highest_severity = max(
            findings,
            key=lambda f: severity_order.get(f.severity, 0)
        ).severity
        
        # Select most recent fixed version
        # Validates: Requirement 8.5 (select most recent fixed version)
        fixed_versions = [
            f.fixed_version for f in findings
            if f.fixed_version and f.fixed_version != "unknown"
        ]
        
        if fixed_versions:
            try:
                # Use packaging.version for proper semantic version comparison
                latest_fixed = max(fixed_versions, key=lambda v: version.parse(v))
            except version.InvalidVersion as e:
                # Fallback to string comparison if version parsing fails
                logger.warning(
                    f"Invalid version format during merge: {e}. Using string comparison.",
                    extra={"versions": fixed_versions}
                )
                latest_fixed = max(fixed_versions)
        else:
            latest_fixed = "unknown"
        
        # Union of CVEs (deduplicated and sorted)
        all_cves = list(set(cve for f in findings for cve in f.cve))
        all_cves.sort()
        
        # Merge metadata from all findings
        # Validates: Requirement 15.4 (preserve scanner-specific metadata)
        merged_metadata = {}
        for f in findings:
            merged_metadata.update(f.metadata)
        
        # Add deduplication tracking metadata
        merged_metadata["deduplicated_from"] = [f.id for f in findings]
        merged_metadata["source_scanners"] = [f.scanner for f in findings]
        
        # Create merged finding
        return NormalizedFinding(
            id=base.id,
            scanner=scanners,
            package_manager=base.package_manager,
            package_name=base.package_name,
            current_version=base.current_version,
            fixed_version=latest_fixed,
            severity=highest_severity,
            cve=all_cves,
            manifest_file=base.manifest_file,
            remediation_type=base.remediation_type,
            repository=base.repository,
            branch=base.branch,
            commit_id=base.commit_id,
            scan_time=base.scan_time,
            metadata=merged_metadata
        )
