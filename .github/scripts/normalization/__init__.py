"""
Normalization Framework for Vulnerability Scanners

This package provides a scanner-agnostic normalization framework for processing
vulnerability findings from multiple security scanners (Snyk, AWS Inspector, etc.).

The framework implements a pluggable adapter pattern that allows new scanners to be
added without modifying core remediation logic.

Key Components:
- framework.py: Core normalization framework with adapter registration
- schema.py: JSON schema definition and validation functions
- models.py: Data models for normalized findings
- adapters/: Scanner-specific adapter implementations

Design Principles:
- Separation of Concerns: Scanner-specific parsing is isolated in adapters
- Single Responsibility: Each component has one clear purpose
- Open/Closed Principle: Open for extension (new adapters), closed for modification
- Fail-Safe Defaults: Invalid findings are logged and excluded, not pipeline-breaking

Usage Example:
    from normalization.framework import NormalizationFramework
    from normalization.adapters.snyk_adapter import SnykAdapter
    
    framework = NormalizationFramework()
    framework.register_adapter("snyk", SnykAdapter())
    
    normalized_findings = framework.normalize("snyk", snyk_json_data)
"""

__version__ = "1.0.0"

from .framework import NormalizationFramework
from .models import NormalizedFinding
from .schema import load_schema, validate_finding

__all__ = [
    "NormalizationFramework",
    "NormalizedFinding",
    "load_schema",
    "validate_finding",
]
