"""
JSON Schema Definition and Validation

This module defines the JSON schema for normalized vulnerability findings and
provides validation functions.

The schema ensures that all normalized findings conform to a common structure,
regardless of the source scanner. This enables scanner-agnostic remediation logic.

Design: The schema uses JSON Schema Draft 7 format for validation. The schema is
defined as a Python dictionary for easy modification and version control.
"""

import logging
from typing import Tuple
import jsonschema
from jsonschema import ValidationError

logger = logging.getLogger(__name__)


def load_schema() -> dict:
    """
    Load the normalized finding JSON schema.
    
    This schema defines the structure and constraints for normalized vulnerability
    findings. All scanner adapters must produce findings that conform to this schema.
    
    Schema Fields:
    - id: Unique identifier for the finding
    - scanner: Source scanner name (e.g., "snyk", "inspector")
    - package_manager: Package manager type (npm, maven, gradle, pip, etc.)
    - package_name: Name of the vulnerable package
    - current_version: Currently installed version
    - fixed_version: Version that fixes the vulnerability
    - severity: Normalized severity level (critical, high, medium, low)
    - cve: List of CVE identifiers
    - manifest_file: Path to manifest file (pom.xml, package.json, etc.)
    - remediation_type: Type of remediation (dependency or code)
    - repository: Repository identifier
    - branch: Branch name (optional, defaults to "main")
    - commit_id: Commit SHA (optional, defaults to "unknown")
    - scan_time: ISO 8601 timestamp of scan
    - metadata: Scanner-specific metadata (extensible)
    
    Returns:
        JSON schema dictionary
    """
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "NormalizedFinding",
        "description": "Normalized vulnerability finding schema for scanner-agnostic remediation",
        "type": "object",
        "required": [
            "id",
            "scanner",
            "package_manager",
            "package_name",
            "current_version",
            "fixed_version",
            "severity",
            "cve",
            "manifest_file",
            "remediation_type",
            "repository"
        ],
        "properties": {
            "id": {
                "type": "string",
                "description": "Unique identifier for the finding",
                "minLength": 1
            },
            "scanner": {
                "type": "string",
                "description": "Source scanner name or comma-separated list for merged findings",
                "minLength": 1
            },
            "package_manager": {
                "type": "string",
                "description": "Package manager type",
                "enum": ["npm", "maven", "gradle", "pip", "pypi", "java", "code", "unknown"]
            },
            "package_name": {
                "type": "string",
                "description": "Package name in package-manager-specific format",
                "minLength": 1
            },
            "current_version": {
                "type": "string",
                "description": "Currently installed version",
                "minLength": 1
            },
            "fixed_version": {
                "type": "string",
                "description": "Version that fixes the vulnerability",
                "minLength": 1
            },
            "severity": {
                "type": "string",
                "description": "Normalized severity level",
                "enum": ["critical", "high", "medium", "low"]
            },
            "cve": {
                "type": "array",
                "description": "List of CVE identifiers",
                "items": {
                    "type": "string",
                    "pattern": "^CVE-[0-9]{4}-[0-9]+$"
                }
            },
            "manifest_file": {
                "type": "string",
                "description": "Path to manifest file",
                "minLength": 1
            },
            "remediation_type": {
                "type": "string",
                "description": "Type of remediation required",
                "enum": ["dependency", "code"]
            },
            "repository": {
                "type": "string",
                "description": "Repository identifier",
                "minLength": 1
            },
            "branch": {
                "type": "string",
                "description": "Branch name",
                "default": "main"
            },
            "commit_id": {
                "type": "string",
                "description": "Commit SHA",
                "default": "unknown"
            },
            "scan_time": {
                "type": "string",
                "description": "ISO 8601 timestamp of scan",
                "format": "date-time"
            },
            "metadata": {
                "type": "object",
                "description": "Scanner-specific metadata (extensible)",
                "additionalProperties": True
            }
        },
        "additionalProperties": False
    }


def validate_finding(finding) -> Tuple[bool, str]:
    """
    Validate a normalized finding against the schema.
    
    This function checks if a NormalizedFinding object conforms to the JSON schema.
    It converts the finding to a dictionary and validates it using jsonschema.
    
    Error Handling: Validation errors are caught and returned as a tuple with
    (False, error_message). This allows the caller to decide how to handle
    validation failures (log, exclude, raise exception, etc.).
    
    Args:
        finding: NormalizedFinding object to validate
    
    Returns:
        Tuple of (is_valid: bool, error_message: str)
        - If valid: (True, "")
        - If invalid: (False, "detailed error message")
    
    Example:
        is_valid, error = validate_finding(finding)
        if not is_valid:
            logger.error(f"Validation failed: {error}")
    """
    schema = load_schema()
    
    try:
        # Convert finding to dictionary for validation
        finding_dict = finding.to_dict()
        
        # Validate against schema
        jsonschema.validate(instance=finding_dict, schema=schema)
        
        return True, ""
        
    except ValidationError as e:
        # Extract detailed error information
        error_path = ".".join(str(p) for p in e.path) if e.path else "root"
        error_message = (
            f"Validation error at '{error_path}': {e.message}. "
            f"Invalid value: {e.instance}"
        )
        return False, error_message
        
    except AttributeError as e:
        # Handle case where finding doesn't have to_dict() method
        error_message = (
            f"Finding object does not have to_dict() method: {e}"
        )
        return False, error_message
        
    except Exception as e:
        # Catch any other unexpected errors
        error_message = f"Unexpected validation error: {type(e).__name__}: {e}"
        return False, error_message
