"""
Scanner Adapters Package

This package contains scanner-specific adapter implementations that parse
vulnerability findings from different security scanners and convert them to
the normalized schema.

Available Adapters:
- base.py: Abstract base class defining the ScannerAdapter interface
- snyk_adapter.py: Adapter for Snyk vulnerability scanner
- inspector_adapter.py: Adapter for AWS Inspector vulnerability scanner

Design Pattern: Adapter Pattern
Each scanner has unique JSON output formats and field names. The adapter pattern
isolates scanner-specific parsing logic, allowing the core framework and remediation
engine to operate on a common normalized schema.

Architecture Decision Record (ADR-001): Pluggable Adapter Pattern
- Decision: Use the adapter pattern for scanner-specific parsing logic
- Rationale: Isolates scanner-specific code, enables independent testing, and allows
  new scanners to be added without modifying core framework
- Consequences: Each scanner requires a dedicated adapter module, but remediation
  logic remains scanner-agnostic

Adding a New Scanner Adapter:
1. Create a new file in this directory (e.g., trivy_adapter.py)
2. Import the ScannerAdapter base class
3. Implement the required methods: parse(), get_scanner_name(), get_scanner_version()
4. Register the adapter with the NormalizationFramework
5. Write unit tests and property tests for the adapter

Example:
    from normalization.adapters.base import ScannerAdapter
    from normalization.models import NormalizedFinding
    
    class TrivyAdapter(ScannerAdapter):
        def parse(self, raw_findings: dict) -> List[NormalizedFinding]:
            # Parse Trivy JSON format
            pass
        
        def get_scanner_name(self) -> str:
            return "trivy"
        
        def get_scanner_version(self) -> str:
            return "0.45.0"
"""

from .base import ScannerAdapter
from .snyk_adapter import SnykAdapter
from .inspector_adapter import InspectorAdapter

__all__ = ["ScannerAdapter", "SnykAdapter", "InspectorAdapter"]
