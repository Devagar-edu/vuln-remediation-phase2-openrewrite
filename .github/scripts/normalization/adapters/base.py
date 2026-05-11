"""
Scanner Adapter Base Interface

This module defines the abstract base class that all scanner adapters must implement.

Design: This interface ensures all adapters provide consistent parsing behavior while
allowing scanner-specific implementation details. The interface defines the contract
between the normalization framework and scanner adapters.

Architecture Decision Record (ADR-001): Pluggable Adapter Pattern
- Decision: Use the adapter pattern for scanner-specific parsing logic
- Rationale: Isolates scanner-specific code, enables independent testing, and allows
  new scanners to be added without modifying core framework
- Consequences: Each scanner requires a dedicated adapter module, but remediation
  logic remains scanner-agnostic

The adapter pattern provides several benefits:
1. Separation of Concerns: Scanner-specific parsing is isolated from core framework
2. Single Responsibility: Each adapter handles one scanner's format
3. Open/Closed Principle: New scanners can be added without modifying existing code
4. Testability: Each adapter can be tested independently
"""

from abc import ABC, abstractmethod
from typing import List


class ScannerAdapter(ABC):
    """
    Abstract base class for scanner adapters.
    
    All scanner adapters must inherit from this class and implement the required
    abstract methods. This ensures consistent behavior across all adapters and
    allows the normalization framework to work with any scanner.
    
    Design Pattern: Template Method Pattern
    The adapter defines the interface (template) that all concrete adapters must
    follow. The framework calls these methods without knowing the specific scanner
    implementation.
    
    Required Methods:
    - parse(): Convert scanner-specific JSON to normalized findings
    - get_scanner_name(): Return unique scanner identifier
    - get_scanner_version(): Return scanner version for audit trail
    
    Implementation Guidelines:
    1. Extract all required fields from scanner-specific format
    2. Map scanner severity levels to normalized levels (critical/high/medium/low)
    3. Preserve scanner-specific metadata in the metadata field
    4. Return all findings; validation happens in the framework
    5. Handle errors gracefully - log and continue processing remaining findings
    
    Example Implementation:
        class SnykAdapter(ScannerAdapter):
            def parse(self, raw_findings: dict) -> List[NormalizedFinding]:
                findings = []
                for vuln in raw_findings.get("vulnerabilities", []):
                    finding = NormalizedFinding(
                        id=vuln["id"],
                        scanner="snyk",
                        package_name=vuln["packageName"],
                        # ... map other fields
                    )
                    findings.append(finding)
                return findings
            
            def get_scanner_name(self) -> str:
                return "snyk"
            
            def get_scanner_version(self) -> str:
                return "1.0.0"
    """
    
    @abstractmethod
    def parse(self, raw_findings: dict) -> List:
        """
        Parse scanner-specific findings into normalized format.
        
        This method is the core responsibility of each adapter. It must:
        1. Parse the scanner-specific JSON structure
        2. Extract all required fields (package, version, severity, CVE, etc.)
        3. Map scanner-specific values to normalized values
        4. Create NormalizedFinding objects
        5. Handle errors gracefully (log and continue)
        
        Error Handling Strategy:
        - If a single finding fails to parse, log the error and continue with
          remaining findings
        - Return all successfully parsed findings
        - Do not raise exceptions for individual finding failures
        - Only raise exceptions for catastrophic failures (invalid JSON structure)
        
        Args:
            raw_findings: Scanner-specific JSON output (typically a dictionary)
        
        Returns:
            List of NormalizedFinding objects (may include invalid findings that
            will be filtered out by schema validation)
        
        Raises:
            Exception: Only for catastrophic parsing failures (invalid JSON structure)
        
        Example:
            adapter = SnykAdapter()
            findings = adapter.parse(snyk_json_data)
        """
        pass
    
    @abstractmethod
    def get_scanner_name(self) -> str:
        """
        Return the unique identifier for this scanner.
        
        This name is used:
        - As the registry key in the normalization framework
        - In the normalized finding's scanner field
        - In log messages and error reports
        - For deduplication (merged findings show "snyk,inspector")
        
        The name should be:
        - Lowercase
        - Alphanumeric (no spaces or special characters)
        - Consistent across all uses
        
        Returns:
            Unique scanner identifier (e.g., "snyk", "inspector", "trivy")
        
        Example:
            adapter = SnykAdapter()
            assert adapter.get_scanner_name() == "snyk"
        """
        pass
    
    @abstractmethod
    def get_scanner_version(self) -> str:
        """
        Return the scanner version for audit trail.
        
        This version is used for:
        - Audit logging
        - Debugging (different versions may have different output formats)
        - Metadata tracking
        
        The version should follow semantic versioning (e.g., "1.2.3") when possible.
        If the scanner version is not available, return "unknown".
        
        Returns:
            Scanner version string (e.g., "1.0.0", "2023.10.15", "unknown")
        
        Example:
            adapter = SnykAdapter()
            version = adapter.get_scanner_version()
        """
        pass
