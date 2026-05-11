"""
Core Normalization Framework

This module implements the core normalization framework that coordinates scanner
adapters and validates normalized findings against the common schema.

Design: This class implements the registry pattern, allowing scanner adapters to be
registered dynamically without modifying core code. This enables the Open/Closed
Principle - the framework is open for extension (new adapters) but closed for
modification (core logic unchanged).

Architecture Decision Record (ADR-001): Pluggable Adapter Pattern
- Decision: Use the adapter pattern for scanner-specific parsing logic
- Rationale: Isolates scanner-specific code, enables independent testing, and allows
  new scanners to be added without modifying core framework
- Consequences: Each scanner requires a dedicated adapter module, but remediation
  logic remains scanner-agnostic
"""

import logging
from typing import Dict, List, Optional
from .models import NormalizedFinding
from .schema import validate_finding
from .adapters.base import ScannerAdapter

logger = logging.getLogger(__name__)


class NormalizationFramework:
    """
    Core framework for scanner-agnostic vulnerability normalization.
    
    This class provides the infrastructure for registering scanner adapters,
    normalizing findings, and validating them against the common schema.
    
    Responsibilities:
    - Define the normalized vulnerability schema
    - Validate normalized findings against the schema
    - Register and manage scanner adapters
    - Coordinate the normalization process
    
    Design Pattern: Registry Pattern
    Scanner adapters are registered dynamically, allowing the framework to support
    multiple scanners without hardcoding scanner-specific logic.
    """
    
    def __init__(self):
        """Initialize the normalization framework."""
        self._adapters: Dict[str, ScannerAdapter] = {}
        logger.info("NormalizationFramework initialized")
    
    def register_adapter(self, scanner_name: str, adapter: ScannerAdapter) -> None:
        """
        Register a scanner adapter with the framework.
        
        This method validates that the adapter implements the required ScannerAdapter
        interface before registration. This ensures all adapters provide consistent
        behavior.
        
        Args:
            scanner_name: Unique identifier for the scanner (e.g., "snyk", "inspector")
            adapter: Instance of a ScannerAdapter implementation
        
        Raises:
            ValueError: If adapter does not implement ScannerAdapter interface
            
        Example:
            framework = NormalizationFramework()
            framework.register_adapter("snyk", SnykAdapter())
        """
        if not isinstance(adapter, ScannerAdapter):
            raise ValueError(
                f"Adapter must implement ScannerAdapter interface. "
                f"Got {type(adapter).__name__} instead."
            )
        
        self._adapters[scanner_name] = adapter
        logger.info(
            f"Registered scanner adapter: {scanner_name}",
            extra={
                "scanner": scanner_name,
                "adapter_class": type(adapter).__name__,
                "scanner_version": adapter.get_scanner_version()
            }
        )
    
    def normalize(
        self,
        scanner_name: str,
        raw_findings: dict
    ) -> List[NormalizedFinding]:
        """
        Normalize findings from a specific scanner.
        
        This method coordinates the normalization process:
        1. Retrieve the registered adapter for the scanner
        2. Parse raw findings using the adapter
        3. Validate each normalized finding against the schema
        4. Exclude invalid findings (with logging)
        5. Return validated findings
        
        Error Handling: Invalid findings are logged and excluded rather than causing
        pipeline failures. This implements the Fail-Safe Default principle - one
        invalid finding should not block remediation of other valid findings.
        
        Args:
            scanner_name: Name of the scanner that produced the findings
            raw_findings: Scanner-specific JSON output
        
        Returns:
            List of validated normalized findings
        
        Raises:
            ValueError: If scanner_name is not registered
            
        Example:
            findings = framework.normalize("snyk", snyk_json_data)
        """
        adapter = self._adapters.get(scanner_name)
        if not adapter:
            available = ", ".join(self._adapters.keys())
            raise ValueError(
                f"No adapter registered for scanner: {scanner_name}. "
                f"Available adapters: {available}"
            )
        
        logger.info(
            f"Starting normalization for scanner: {scanner_name}",
            extra={"scanner": scanner_name}
        )
        
        # Parse raw findings using the adapter
        try:
            normalized = adapter.parse(raw_findings)
            logger.info(
                f"Adapter parsed {len(normalized)} findings",
                extra={"scanner": scanner_name, "finding_count": len(normalized)}
            )
        except Exception as e:
            logger.error(
                f"Adapter parsing failed for {scanner_name}: {e}",
                extra={"scanner": scanner_name, "error": str(e)},
                exc_info=True
            )
            raise
        
        # Validate each finding against the schema
        validated = []
        for finding in normalized:
            if self._validate(finding):
                validated.append(finding)
        
        invalid_count = len(normalized) - len(validated)
        if invalid_count > 0:
            logger.warning(
                f"Excluded {invalid_count} invalid findings from {scanner_name}",
                extra={
                    "scanner": scanner_name,
                    "total_findings": len(normalized),
                    "valid_findings": len(validated),
                    "invalid_findings": invalid_count
                }
            )
        
        logger.info(
            f"Normalization complete: {len(validated)} valid findings",
            extra={"scanner": scanner_name, "valid_findings": len(validated)}
        )
        
        return validated
    
    def _validate(self, finding: NormalizedFinding) -> bool:
        """
        Validate a normalized finding against the schema.
        
        This method uses the schema validation function to check if the finding
        conforms to the normalized schema. Invalid findings are logged with full
        context for debugging.
        
        Error Logging: Validation errors are logged with structured context including:
        - Scanner name
        - Finding ID
        - Validation error details
        
        This satisfies Requirement 13.5: validation error logs must contain scanner
        name, finding ID, and validation failure reason.
        
        Args:
            finding: Normalized finding to validate
        
        Returns:
            True if valid, False otherwise (logs validation errors)
        """
        is_valid, error_message = validate_finding(finding)
        
        if not is_valid:
            logger.error(
                f"Schema validation failed for finding {finding.id}",
                extra={
                    "component": "NormalizationFramework",
                    "scanner": finding.scanner,
                    "finding_id": finding.id,
                    "error_type": "SchemaValidationError",
                    "error_message": error_message,
                    "package_name": finding.package_name,
                    "package_manager": finding.package_manager
                }
            )
        
        return is_valid
    
    def get_registered_adapters(self) -> List[str]:
        """
        Get list of registered scanner adapter names.
        
        Returns:
            List of scanner names that have registered adapters
        """
        return list(self._adapters.keys())
