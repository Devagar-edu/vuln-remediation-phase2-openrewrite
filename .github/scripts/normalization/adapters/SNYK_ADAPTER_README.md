# Snyk Scanner Adapter

## Overview

The `SnykAdapter` is a scanner adapter implementation that parses Snyk vulnerability findings and converts them to the normalized schema used by the remediation pipeline.

This adapter refactors the existing `normalize.py` logic into the pluggable adapter pattern while maintaining 100% backward compatibility.

## Features

- **Dependency Vulnerability Parsing**: Parses Snyk dependency scan results (JSON format)
- **Code Vulnerability Parsing**: Parses Snyk code scan results (SARIF format)
- **Version Extraction**: Handles various version string formats (e.g., `5.3.20.RELEASE`, `package@5.3.20`)
- **Vulnerability Grouping**: Groups multiple vulnerabilities for the same package
- **Severity Selection**: Selects highest severity when multiple vulnerabilities exist
- **Fix Version Selection**: Selects most recent fix version from multiple sources
- **Metadata Preservation**: Preserves all Snyk-specific metadata in normalized output

## Usage

### Basic Usage

```python
from normalization.adapters import SnykAdapter
from normalization.framework import NormalizationFramework

# Create adapter instance
adapter = SnykAdapter()

# Register with framework
framework = NormalizationFramework()
framework.register_adapter("snyk", adapter)

# Parse Snyk findings
with open("snyk-results.json") as f:
    snyk_data = json.load(f)

normalized_findings = framework.normalize("snyk", snyk_data)
```

### Direct Parsing

```python
from normalization.adapters import SnykAdapter

adapter = SnykAdapter()

# Parse dependency vulnerabilities
snyk_dependency_data = {
    "vulnerabilities": [
        {
            "id": "SNYK-JAVA-ORGSPRINGFRAMEWORK-12345",
            "packageName": "org.springframework:spring-core",
            "version": "5.3.0",
            "title": "Denial of Service (DoS)",
            "severity": "high",
            "identifiers": {"CVE": ["CVE-2023-1234"]},
            "upgradePath": ["org.springframework:spring-core@5.3.20"],
            # ... other fields
        }
    ]
}

findings = adapter.parse(snyk_dependency_data)
```

## Input Formats

### Dependency Scan Format

The adapter expects Snyk dependency scan output in the following format:

```json
{
  "vulnerabilities": [
    {
      "id": "SNYK-JAVA-ORGSPRINGFRAMEWORK-12345",
      "packageName": "org.springframework:spring-core",
      "version": "5.3.0",
      "title": "Denial of Service (DoS)",
      "severity": "high",
      "cvssScore": 7.5,
      "identifiers": {
        "CVE": ["CVE-2023-1234"],
        "CWE": ["CWE-400"]
      },
      "description": "A vulnerability in Spring Framework...",
      "upgradePath": ["org.springframework:spring-core@5.3.20"],
      "exploit": "Not Defined"
    }
  ]
}
```

### Code Scan Format (SARIF)

The adapter expects Snyk code scan output in SARIF format:

```json
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "java/sql-injection",
              "name": "SQL Injection",
              "shortDescription": {
                "text": "Unsanitized input from HTTP request is used in SQL query"
              },
              "properties": {
                "cwe": ["CWE-89"],
                "tags": ["security", "sql"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "java/sql-injection",
          "ruleIndex": 0,
          "level": "error",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/main/java/com/example/UserController.java"
                },
                "region": {
                  "startLine": 42
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Output Format

The adapter produces `NormalizedFinding` objects with the following structure:

```python
NormalizedFinding(
    id="<UUID or Snyk ID>",
    scanner="snyk",
    package_manager="maven",  # Inferred from package name
    package_name="org.springframework:spring-core",
    current_version="5.3.0",
    fixed_version="5.3.20",
    severity="high",
    cve=["CVE-2023-1234"],
    manifest_file="pom.xml",  # Inferred from package manager
    remediation_type="dependency",
    repository="demo-repo",
    branch="main",
    commit_id="unknown",
    metadata={
        "snyk_vulnerabilities": [...],  # Original vulnerability details
        "snyk_package": "org.springframework:spring-core",
        "snyk_current_version": "5.3.0"
    }
)
```

## Implementation Details

### Version Extraction

The adapter uses the `_extract_version()` method to handle various version string formats:

- `5.3.20` → `5.3.20`
- `package@5.3.20` → `5.3.20`
- `5.3.20.RELEASE` → `5.3.20`
- `5.3.20.FINAL` → `5.3.20`
- `5.3.20-beta` → `5.3.20`

### Package Manager Inference

The adapter infers the package manager from the package name format:

- `org.springframework:spring-core` → `maven` (contains `:` and `.` in groupId)
- `django-rest-framework` → `pip` (contains `-` or `_`)
- `lodash` → `npm` (default for simple names)

### Severity Mapping

The adapter maps Snyk severity levels to normalized levels:

- Dependency scans: `critical`, `high`, `medium`, `low` (direct mapping)
- Code scans (SARIF): `error` → `high`, `warning` → `medium`, `note` → `low`

### Vulnerability Grouping

When multiple vulnerabilities affect the same package:

1. Vulnerabilities are grouped by package name
2. The highest severity is selected
3. The most recent fix version is selected
4. All CVEs are combined (deduplicated)
5. All vulnerability details are preserved in metadata

## Backward Compatibility

The adapter maintains 100% backward compatibility with the original `normalize.py` script:

- Preserves all existing parsing logic
- Produces identical normalized output
- Maintains all Snyk-specific metadata
- Uses the same version extraction algorithm
- Applies the same severity selection rules

## Testing

### Unit Tests

Run the unit tests:

```bash
python -m pytest .github/scripts/normalization/adapters/test_snyk_adapter.py -v
```

### Backward Compatibility Verification

Verify backward compatibility:

```bash
python .github/scripts/normalization/adapters/verify_backward_compatibility.py
```

## Error Handling

The adapter handles errors gracefully:

- **Invalid Input**: Logs error and continues processing remaining findings
- **Missing Fields**: Uses default values or "unknown" for optional fields
- **Version Parsing Errors**: Falls back to "0" for invalid version strings
- **Empty Input**: Returns empty list without raising exceptions

## Metadata Preservation

The adapter preserves all Snyk-specific metadata in the `metadata` field:

### Dependency Vulnerabilities

```python
metadata = {
    "snyk_vulnerabilities": [
        {
            "id": "SNYK-JAVA-ORGSPRINGFRAMEWORK-12345",
            "title": "Denial of Service (DoS)",
            "severity": "high",
            "cvss": 7.5,
            "cve": ["CVE-2023-1234"],
            "cwe": ["CWE-400"],
            "exploit": "Not Defined",
            "description": "..."
        }
    ],
    "snyk_package": "org.springframework:spring-core",
    "snyk_current_version": "5.3.0"
}
```

### Code Vulnerabilities

```python
metadata = {
    "snyk_rule_id": "java/sql-injection",
    "snyk_rule_name": "SQL Injection",
    "snyk_description": "Unsanitized input from HTTP request...",
    "snyk_cwe": ["CWE-89"],
    "snyk_tags": ["security", "sql"],
    "snyk_occurrences": [
        {
            "file": "src/main/java/com/example/UserController.java",
            "line": 42
        }
    ]
}
```

## Architecture Decisions

### ADR-004: Backward Compatibility Requirement

- **Decision**: Existing Snyk workflow must produce identical outputs after refactoring
- **Rationale**: Minimize risk and deployment complexity; allow gradual rollout
- **Consequences**: Refactoring preserves all existing logic exactly

### Design Principles

- **Separation of Concerns**: Scanner-specific parsing is isolated in the adapter
- **Single Responsibility**: The adapter only handles Snyk format parsing
- **Fail-Safe Defaults**: Invalid findings are logged and excluded, not pipeline-breaking

## Future Enhancements

Potential improvements for future versions:

1. **Dynamic Repository Detection**: Extract repository information from Snyk metadata
2. **Enhanced Version Comparison**: Support more complex version schemes (semantic versioning, date-based versions)
3. **Configurable Defaults**: Allow customization of default values (repository, branch)
4. **Performance Optimization**: Batch processing for large scan results
5. **Streaming Support**: Process large JSON files without loading entire content into memory

## Related Documentation

- [Scanner Adapter Base Class](./base.py)
- [Normalized Finding Schema](../models.py)
- [Normalization Framework](../framework.py)
- [Design Document](../../../../.kiro/specs/aws-inspector-integration/design.md)
- [Requirements Document](../../../../.kiro/specs/aws-inspector-integration/requirements.md)
