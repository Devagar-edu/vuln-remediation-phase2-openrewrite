# AWS Inspector Scanner Adapter

## Overview

The Inspector adapter parses AWS Inspector vulnerability findings and converts them to the normalized finding format. It implements **application dependency filtering** as a core feature, focusing exclusively on vulnerabilities in application-level dependencies (npm, Maven, Gradle, pip) and excluding OS-level packages.

## Architecture Decision

**ADR-002: Application Dependency Filtering**
- **Decision**: Filter Inspector findings to application dependencies only
- **Rationale**: OS-level vulnerabilities require different remediation strategies (infrastructure updates, container base image changes) that are outside the scope of application code remediation
- **Consequences**: Some Inspector findings will be excluded; separate workflows may be needed for infrastructure vulnerabilities

## Features

### 1. Application Dependency Filtering

The adapter implements strict filtering to include only application dependencies:

**Included Package Managers:**
- `npm` - Node.js packages
- `maven` - Maven/Java packages
- `gradle` - Gradle/Java packages
- `pip` / `pypi` - Python packages
- `java` - Java packages

**Excluded Package Managers:**
- `apt` - Debian/Ubuntu OS packages
- `yum` - RedHat/CentOS OS packages
- `apk` - Alpine Linux OS packages
- `rpm` - RPM-based OS packages
- `dpkg` - Debian package manager

**Filtering Logic:**
1. Check `packageVulnerabilityDetails.vulnerablePackages[].packageManager`
2. Include if package manager is in the application list
3. Exclude if package manager is in the OS list
4. Exclude if source is "OS" or "OPERATING_SYSTEM"
5. Default to exclude if uncertain (fail-safe)

### 2. Inspector Field Mapping

The adapter maps Inspector-specific fields to the normalized schema:

| Inspector Field | Normalized Field | Notes |
|----------------|------------------|-------|
| `findingArn` | `id` | Unique finding identifier |
| `severity` | `severity` | Mapped to normalized levels |
| `vulnerablePackages[].packageManager` | `package_manager` | Lowercase |
| `vulnerablePackages[].name` | `package_name` | Full package name |
| `vulnerablePackages[].version` | `current_version` | Currently installed version |
| `vulnerablePackages[].fixedInVersion` | `fixed_version` | Version that fixes the vulnerability |
| `vulnerabilityId` | `cve` | CVE identifier |
| `type` | `remediation_type` | "dependency" or "code" |
| `resources[].id` | `repository` | Extracted from ECR ARN |

### 3. Severity Mapping

Inspector severity levels are mapped to normalized levels:

| Inspector Severity | Normalized Severity |
|-------------------|---------------------|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFORMATIONAL` | `low` |
| `UNTRIAGED` | `medium` (default) |

### 4. Fixed Version Extraction

The adapter extracts fixed versions using multiple strategies:

1. **Primary**: Check `vulnerablePackages[].fixedInVersion` field
2. **Fallback**: Parse `remediation.recommendation.text` for version patterns
3. **Default**: Return "unknown" if no version found

Example remediation text parsing:
```
"Upgrade io.netty:netty-handler to version 4.1.118.Final or later"
→ Extracts: "4.1.118.Final"
```

### 5. CVE Extraction

CVEs are extracted from multiple sources:

1. **Primary**: `packageVulnerabilityDetails.vulnerabilityId`
2. **Additional**: `packageVulnerabilityDetails.relatedVulnerabilities[].id`

All CVEs are deduplicated and returned as a list.

### 6. Metadata Preservation

All Inspector-specific metadata is preserved in the `metadata` field:

```python
{
    "inspector_finding_arn": "arn:aws:inspector2:...",
    "inspector_title": "CVE-2025-24970 - io.netty:netty-handler",
    "inspector_description": "Netty vulnerability description...",
    "inspector_first_observed": "2026-05-08T10:30:00.000Z",
    "inspector_last_observed": "2026-05-08T10:30:00.000Z",
    "inspector_exploit_available": "NO",
    "inspector_fix_available": "YES",
    "inspector_epss_score": 0.00234,
    "inspector_cvss": [...],
    "inspector_reference_urls": [...],
    "inspector_file_path": "/app/vulnerable-demo-1.0.0.jar/..."
}
```

## Usage

### Basic Usage

```python
from adapters.inspector_adapter import InspectorAdapter
import json

# Load Inspector findings
with open('aws-inspector-findings.json', 'r') as f:
    raw_findings = json.load(f)

# Initialize adapter
adapter = InspectorAdapter()

# Parse findings
normalized_findings = adapter.parse(raw_findings)

# Process normalized findings
for finding in normalized_findings:
    print(f"Package: {finding.package_name}")
    print(f"Current: {finding.current_version}")
    print(f"Fixed: {finding.fixed_version}")
    print(f"Severity: {finding.severity}")
    print(f"CVE: {', '.join(finding.cve)}")
```

### Integration with Normalization Framework

```python
from normalization_framework import NormalizationFramework
from adapters.inspector_adapter import InspectorAdapter

# Register adapter
framework = NormalizationFramework()
framework.register_adapter("inspector", InspectorAdapter())

# Normalize findings
normalized = framework.normalize("inspector", raw_findings)
```

## Inspector JSON Format

The adapter expects Inspector findings in the following format:

```json
{
  "findings": [
    {
      "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/...",
      "severity": "CRITICAL",
      "type": "PACKAGE_VULNERABILITY",
      "title": "CVE-2025-24970 - io.netty:netty-handler",
      "description": "Vulnerability description...",
      "packageVulnerabilityDetails": {
        "vulnerabilityId": "CVE-2025-24970",
        "source": "NVD",
        "vulnerablePackages": [
          {
            "name": "io.netty:netty-handler",
            "version": "4.1.115.Final",
            "packageManager": "JAVA",
            "fixedInVersion": "4.1.118.Final",
            "filePath": "/app/vulnerable-demo-1.0.0.jar/..."
          }
        ],
        "relatedVulnerabilities": [],
        "cvss": [...],
        "referenceUrls": [...]
      },
      "remediation": {
        "recommendation": {
          "text": "Upgrade io.netty:netty-handler to version 4.1.118.Final or later"
        }
      },
      "resources": [
        {
          "id": "arn:aws:ecr:us-east-1:123456789012:repository/vulnerable-demo/...",
          "type": "AWS_ECR_CONTAINER_IMAGE"
        }
      ],
      "firstObservedAt": "2026-05-08T10:30:00.000Z",
      "lastObservedAt": "2026-05-08T10:30:00.000Z"
    }
  ]
}
```

## Testing

Run the test suite to verify the adapter:

```bash
python .github/scripts/normalization/adapters/test_inspector_adapter.py
```

The test suite verifies:
1. ✓ Filtering logic (application vs OS dependencies)
2. ✓ Field mapping and normalization
3. ✓ CVE extraction
4. ✓ Severity mapping
5. ✓ Fixed version extraction
6. ✓ Metadata preservation
7. ✓ Required fields population

## Example Output

### Input (Inspector Finding)
```json
{
  "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve202524970-001",
  "severity": "CRITICAL",
  "packageVulnerabilityDetails": {
    "vulnerabilityId": "CVE-2025-24970",
    "vulnerablePackages": [
      {
        "name": "io.netty:netty-handler",
        "version": "4.1.115.Final",
        "packageManager": "JAVA",
        "fixedInVersion": "4.1.118.Final"
      }
    ]
  }
}
```

### Output (Normalized Finding)
```python
NormalizedFinding(
    id="arn:aws:inspector2:us-east-1:123456789012:finding/cve202524970-001",
    scanner="inspector",
    package_manager="java",
    package_name="io.netty:netty-handler",
    current_version="4.1.115.Final",
    fixed_version="4.1.118.Final",
    severity="critical",
    cve=["CVE-2025-24970"],
    manifest_file="pom.xml",
    remediation_type="dependency",
    repository="vulnerable-demo",
    metadata={
        "inspector_finding_arn": "arn:aws:inspector2:...",
        "inspector_title": "CVE-2025-24970 - io.netty:netty-handler",
        ...
    }
)
```

## Requirements Satisfied

This implementation satisfies the following requirements:

- **Requirement 4.1**: Parse AWS Inspector JSON output format ✓
- **Requirement 4.2**: Extract package manager, package name, versions, severity, CVE ✓
- **Requirement 4.3**: Implement Inspector finding normalization ✓
- **Requirement 4.4**: Implement fixed version extraction ✓
- **Requirement 5.1**: Process npm, Maven, Gradle, pip package managers ✓
- **Requirement 5.2**: Ignore apt, yum, apk, rpm package managers ✓
- **Requirement 5.3**: Map Inspector severity to normalized levels ✓
- **Requirement 5.4**: Extract fixed version from fixedInVersion field ✓
- **Requirement 5.5**: Extract CVE from vulnerabilityId field ✓
- **Requirement 5.6**: Preserve Inspector-specific metadata ✓

## Design Principles

1. **Separation of Concerns**: Filtering logic is isolated in `_is_application_dependency()`
2. **Single Responsibility**: Each helper method has one clear purpose
3. **Fail-Safe Defaults**: Unknown package managers are excluded by default
4. **Metadata Preservation**: All Inspector-specific data is preserved for audit trail
5. **Error Handling**: Gracefully handles missing fields with sensible defaults

## Future Enhancements

Potential future improvements:

1. **Configurable Filtering**: Allow custom package manager inclusion/exclusion lists
2. **Enhanced Version Parsing**: Support more version string formats
3. **Multi-CVE Handling**: Better handling of findings with multiple CVEs
4. **Repository Extraction**: Improved repository name extraction from various resource types
5. **Batch Processing**: Optimize for large Inspector finding sets

## Related Documentation

- [Base Adapter Interface](./base.py) - Abstract base class for all adapters
- [Snyk Adapter](./snyk_adapter.py) - Reference implementation
- [Normalized Finding Model](../models.py) - Data model specification
- [Sample Data Documentation](../../SAMPLE_DATA_DOCUMENTATION.md) - Complete examples of input/output formats
- [Design Document](../../../../.kiro/specs/aws-inspector-integration/design.md) - Overall architecture
