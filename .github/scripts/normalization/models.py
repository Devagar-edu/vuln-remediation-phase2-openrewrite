"""
Data Models for Normalized Findings

This module defines the data models used throughout the normalization framework.

Design: Uses Python dataclasses for immutability, type safety, and automatic
generation of __init__, __repr__, and __eq__ methods. The metadata field provides
extensibility for scanner-specific data without modifying the core schema.

Architecture Decision Record (ADR-003): CVE-Based Deduplication
- Decision: Use CVE + package name + version as the deduplication key
- Rationale: CVE is the most reliable cross-scanner identifier for the same vulnerability
- Consequences: Vulnerabilities without CVEs may not be deduplicated; scanner-specific
  IDs are preserved in metadata
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class NormalizedFinding:
    """
    Normalized vulnerability finding schema.
    
    This schema is the single source of truth for vulnerability data across all
    scanners. All scanner-specific fields are mapped to these common fields.
    
    Design: Uses dataclass for immutability and type safety. The metadata field
    provides extensibility for scanner-specific data without modifying the schema.
    This satisfies Requirement 10.2: the normalized schema must accommodate
    scanner-specific metadata through an extensible metadata field.
    
    Fields:
        id: Unique identifier (scanner-specific ID or generated UUID)
        scanner: Source scanner name (e.g., "snyk", "inspector", "snyk,inspector")
        package_manager: Package manager (npm, maven, gradle, pip, etc.)
        package_name: Package name (e.g., "org.springframework.boot:spring-boot-starter-web")
        current_version: Currently installed version
        fixed_version: Version that fixes the vulnerability (or "unknown")
        severity: Normalized severity (critical, high, medium, low)
        cve: List of CVE identifiers
        manifest_file: Path to manifest file (pom.xml, package.json, requirements.txt)
        remediation_type: Type of remediation ("dependency" or "code")
        repository: Repository identifier
        branch: Branch name (default: "main")
        commit_id: Commit SHA (default: "unknown")
        scan_time: ISO 8601 timestamp of scan
        metadata: Scanner-specific metadata (extensible)
    
    Example:
        finding = NormalizedFinding(
            id="CVE-2023-1234",
            scanner="snyk",
            package_manager="maven",
            package_name="org.springframework:spring-core",
            current_version="5.3.0",
            fixed_version="5.3.20",
            severity="high",
            cve=["CVE-2023-1234"],
            manifest_file="pom.xml",
            remediation_type="dependency",
            repository="my-org/my-repo",
            metadata={"snyk_id": "SNYK-JAVA-ORGSPRINGFRAMEWORK-12345"}
        )
    """
    
    # Core identification
    id: str
    scanner: str
    
    # Package information
    package_manager: str
    package_name: str
    current_version: str
    fixed_version: str
    
    # Vulnerability details
    severity: str
    cve: List[str]
    
    # Remediation information
    manifest_file: str
    remediation_type: str
    
    # Context
    repository: str
    branch: str = "main"
    commit_id: str = "unknown"
    scan_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Extensibility
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """
        Convert to dictionary for JSON serialization.
        
        This method is used by the schema validation function and for generating
        JSON output for Jira tickets and pull requests.
        
        Returns:
            Dictionary representation of the finding
        """
        return {
            "id": self.id,
            "scanner": self.scanner,
            "package_manager": self.package_manager,
            "package_name": self.package_name,
            "current_version": self.current_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity,
            "cve": self.cve,
            "manifest_file": self.manifest_file,
            "remediation_type": self.remediation_type,
            "repository": self.repository,
            "branch": self.branch,
            "commit_id": self.commit_id,
            "scan_time": self.scan_time,
            "metadata": self.metadata
        }
    
    def __str__(self) -> str:
        """
        Human-readable string representation.
        
        Returns:
            String representation for logging and debugging
        """
        cve_str = ", ".join(self.cve) if self.cve else "No CVE"
        return (
            f"NormalizedFinding(id={self.id}, scanner={self.scanner}, "
            f"package={self.package_name}, version={self.current_version}, "
            f"severity={self.severity}, cve=[{cve_str}])"
        )


@dataclass
class DependencyChange:
    """
    Represents a planned dependency upgrade.
    
    This model is used by the compatibility analyzer to track dependency changes
    that require code compatibility analysis.
    
    Fields:
        package_name: Name of the package being upgraded
        current_version: Currently installed version
        target_version: Target version to upgrade to
        package_manager: Package manager (npm, maven, gradle, pip)
    """
    package_name: str
    current_version: str
    target_version: str
    package_manager: str


@dataclass
class BreakingChange:
    """
    Represents a breaking change in a dependency upgrade.
    
    This model is used by the compatibility analyzer to track breaking API changes
    that require code fixes.
    
    Fields:
        change_type: Type of breaking change (removed, renamed, signature_changed, etc.)
        affected_api: Method/class/function name that changed
        description: Human-readable description of the change
        migration_guide: Optional migration guide or documentation URL
    """
    change_type: str
    affected_api: str
    description: str
    migration_guide: Optional[str] = None


@dataclass
class CodeFix:
    """
    Represents a code fix for dependency compatibility.
    
    This model is used by the compatibility analyzer to track code changes required
    to maintain compatibility with upgraded dependencies.
    
    Fields:
        file_path: Path to the file that needs fixing
        original_code: Original code snippet
        fixed_code: Fixed code snippet
        reason: Explanation of why the fix is needed
    """
    file_path: str
    original_code: str
    fixed_code: str
    reason: str


@dataclass
class BuildResult:
    """
    Represents the result of a build validation.
    
    This model is used by the compatibility analyzer to track build execution
    results and any errors encountered.
    
    Fields:
        success: Whether the build succeeded
        errors: List of error messages from the build
        output: Full build output (stdout + stderr)
        command: The build command that was executed
        exit_code: Exit code from the build process
    """
    success: bool
    errors: List[str] = field(default_factory=list)
    output: str = ""
    command: str = ""
    exit_code: int = 0


@dataclass
class TestResult:
    """
    Represents the result of test execution.
    
    This model is used by the compatibility analyzer to track test execution
    results and any failures encountered.
    
    Fields:
        success: Whether all tests passed
        failures: List of test failure messages
        output: Full test output (stdout + stderr)
        command: The test command that was executed
        exit_code: Exit code from the test process
        tests_run: Number of tests executed
        tests_failed: Number of tests that failed
    """
    success: bool
    failures: List[str] = field(default_factory=list)
    output: str = ""
    command: str = ""
    exit_code: int = 0
    tests_run: int = 0
    tests_failed: int = 0
