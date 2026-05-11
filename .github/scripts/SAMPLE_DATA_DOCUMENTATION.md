# Sample Data Documentation

This document provides comprehensive examples of AWS Inspector input data and the corresponding normalized and deduplicated outputs produced by the normalization framework.

## Table of Contents

1. [Sample AWS Inspector JSON Input](#sample-aws-inspector-json-input)
2. [Sample Normalized Output](#sample-normalized-output)
3. [Sample Deduplicated Output](#sample-deduplicated-output)
4. [Field Mapping Reference](#field-mapping-reference)
5. [Filtering Examples](#filtering-examples)

---

## Sample AWS Inspector JSON Input

This example shows raw AWS Inspector findings JSON format. Note that it contains both **application dependency vulnerabilities** (npm) and **OS-level vulnerabilities** (apt), demonstrating the filtering behavior.

```json
{
  "findings": [
    {
      "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/0123456789abcdef",
      "awsAccountId": "123456789012",
      "type": "PACKAGE_VULNERABILITY",
      "description": "CVE-2023-1234 - Arbitrary code execution vulnerability in lodash",
      "title": "CVE-2023-1234 - lodash",
      "severity": "HIGH",
      "firstObservedAt": "2024-01-15T10:30:00Z",
      "lastObservedAt": "2024-01-15T10:30:00Z",
      "status": "ACTIVE",
      "packageVulnerabilityDetails": {
        "source": "NVD",
        "vulnerablePackages": [
          {
            "name": "lodash",
            "version": "4.17.19",
            "packageManager": "npm",
            "filePath": "/app/package.json",
            "fixedInVersion": "4.17.21"
          }
        ],
        "relatedVulnerabilities": [
          {
            "id": "CVE-2023-1234",
            "cvss": {
              "baseScore": 7.5,
              "scoringVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            }
          }
        ]
      },
      "remediation": {
        "recommendation": {
          "text": "Upgrade lodash to version 4.17.21 or later"
        }
      },
      "resources": [
        {
          "id": "arn:aws:ecr:us-east-1:123456789012:repository/my-app",
          "type": "AWS_ECR_CONTAINER_IMAGE"
        }
      ]
    },
    {
      "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/abcdef0123456789",
      "awsAccountId": "123456789012",
      "type": "PACKAGE_VULNERABILITY",
      "description": "CVE-2023-5678 - OS-level vulnerability in openssl",
      "title": "CVE-2023-5678 - openssl",
      "severity": "CRITICAL",
      "firstObservedAt": "2024-01-15T10:30:00Z",
      "lastObservedAt": "2024-01-15T10:30:00Z",
      "status": "ACTIVE",
      "packageVulnerabilityDetails": {
        "source": "OS",
        "vulnerablePackages": [
          {
            "name": "openssl",
            "version": "1.1.1k",
            "packageManager": "apt",
            "filePath": "/var/lib/dpkg/status",
            "fixedInVersion": "1.1.1n"
          }
        ],
        "relatedVulnerabilities": [
          {
            "id": "CVE-2023-5678",
            "cvss": {
              "baseScore": 9.8,
              "scoringVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
          }
        ]
      },
      "remediation": {
        "recommendation": {
          "text": "Update base image to include openssl 1.1.1n"
        }
      },
      "resources": [
        {
          "id": "arn:aws:ecr:us-east-1:123456789012:repository/my-app",
          "type": "AWS_ECR_CONTAINER_IMAGE"
        }
      ]
    }
  ]
}
```

### Key Observations

- **Finding 1 (lodash)**: Application dependency with `packageManager: "npm"` → **INCLUDED** in normalized output
- **Finding 2 (openssl)**: OS-level package with `packageManager: "apt"` and `source: "OS"` → **FILTERED OUT** from normalized output

---

## Sample Normalized Output

This example shows the normalized output after processing the Inspector JSON through the normalization framework. Notice that only the application dependency (lodash) is included, while the OS-level package (openssl) has been filtered out.

```json
{
  "scan_metadata": {
    "scanner": "inspector",
    "scan_time": "2024-01-15T10:35:00Z",
    "findings_count": 1
  },
  "findings": [
    {
      "id": "arn:aws:inspector2:us-east-1:123456789012:finding/0123456789abcdef",
      "scanner": "inspector",
      "package_manager": "npm",
      "package_name": "lodash",
      "current_version": "4.17.19",
      "fixed_version": "4.17.21",
      "severity": "high",
      "cve": ["CVE-2023-1234"],
      "manifest_file": "/app/package.json",
      "remediation_type": "dependency",
      "repository": "arn:aws:ecr:us-east-1:123456789012:repository/my-app",
      "branch": "main",
      "commit_id": "unknown",
      "scan_time": "2024-01-15T10:35:00Z",
      "metadata": {
        "inspector_finding_arn": "arn:aws:inspector2:us-east-1:123456789012:finding/0123456789abcdef",
        "inspector_title": "CVE-2023-1234 - lodash",
        "inspector_description": "CVE-2023-1234 - Arbitrary code execution vulnerability in lodash",
        "inspector_first_observed": "2024-01-15T10:30:00Z",
        "inspector_last_observed": "2024-01-15T10:30:00Z",
        "inspector_cvss_score": 7.5,
        "inspector_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
      }
    }
  ]
}
```

### Normalized Schema Fields

All normalized findings conform to the following schema:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | string | Unique identifier | `"arn:aws:inspector2:..."` |
| `scanner` | string | Source scanner name | `"inspector"` |
| `package_manager` | string | Package manager type | `"npm"`, `"maven"`, `"gradle"`, `"pip"` |
| `package_name` | string | Package name | `"lodash"` |
| `current_version` | string | Currently installed version | `"4.17.19"` |
| `fixed_version` | string | Version that fixes vulnerability | `"4.17.21"` |
| `severity` | string | Normalized severity level | `"critical"`, `"high"`, `"medium"`, `"low"` |
| `cve` | array[string] | List of CVE identifiers | `["CVE-2023-1234"]` |
| `manifest_file` | string | Path to manifest file | `"/app/package.json"` |
| `remediation_type` | string | Type of remediation needed | `"dependency"` or `"code"` |
| `repository` | string | Repository identifier | `"arn:aws:ecr:..."` |
| `branch` | string | Branch name | `"main"` |
| `commit_id` | string | Commit SHA | `"abc123"` or `"unknown"` |
| `scan_time` | string | ISO 8601 timestamp | `"2024-01-15T10:35:00Z"` |
| `metadata` | object | Scanner-specific metadata | See below |

### Inspector-Specific Metadata

The `metadata` field preserves Inspector-specific information:

- `inspector_finding_arn`: Original Inspector finding ARN
- `inspector_title`: Inspector finding title
- `inspector_description`: Inspector finding description
- `inspector_first_observed`: First observation timestamp
- `inspector_last_observed`: Last observation timestamp
- `inspector_cvss_score`: CVSS base score
- `inspector_cvss_vector`: CVSS scoring vector

---

## Sample Deduplicated Output

This example demonstrates deduplication when both Snyk and AWS Inspector report the same vulnerability (same CVE, package, and version). The deduplication service merges the findings into a single record that preserves information from both scanners.

### Scenario

- **Snyk** reports: lodash 4.17.19 vulnerable to CVE-2023-1234, fix available in 4.17.21
- **Inspector** reports: lodash 4.17.19 vulnerable to CVE-2023-1234, fix available in 4.17.21

### Deduplicated Output

```json
{
  "scan_metadata": {
    "scanner": "snyk,inspector",
    "scan_time": "2024-01-15T10:40:00Z",
    "findings_count": 1
  },
  "findings": [
    {
      "id": "snyk-12345",
      "scanner": "snyk,inspector",
      "package_manager": "npm",
      "package_name": "lodash",
      "current_version": "4.17.19",
      "fixed_version": "4.17.21",
      "severity": "high",
      "cve": ["CVE-2023-1234"],
      "manifest_file": "package.json",
      "remediation_type": "dependency",
      "repository": "my-org/my-repo",
      "branch": "main",
      "commit_id": "abc123",
      "scan_time": "2024-01-15T10:40:00Z",
      "metadata": {
        "deduplicated_from": [
          "snyk-12345",
          "arn:aws:inspector2:us-east-1:123456789012:finding/0123456789abcdef"
        ],
        "source_scanners": ["snyk", "inspector"],
        "snyk_id": "SNYK-JS-LODASH-1234567",
        "snyk_severity": "high",
        "snyk_exploit_maturity": "mature",
        "inspector_finding_arn": "arn:aws:inspector2:us-east-1:123456789012:finding/0123456789abcdef",
        "inspector_cvss_score": 7.5
      }
    }
  ]
}
```

### Deduplication Logic

The deduplication service uses the following key to identify duplicates:

```
(CVE, package_name, current_version, repository)
```

When duplicates are found, the merge strategy is:

1. **Scanner**: Combine all scanner names (comma-separated): `"snyk,inspector"`
2. **Severity**: Select the highest severity level
3. **Fixed Version**: Select the most recent version
4. **CVE List**: Union of all CVE identifiers
5. **Metadata**: Merge all scanner-specific metadata
6. **Audit Trail**: Add `deduplicated_from` and `source_scanners` fields

### Deduplication Benefits

- **Single Jira Ticket**: Only one ticket is created for the vulnerability
- **Single Remediation**: Only one PR is created to fix the vulnerability
- **Complete Context**: Metadata from both scanners is preserved
- **Audit Trail**: Original finding IDs are tracked in `deduplicated_from`

---

## Field Mapping Reference

### Inspector → Normalized Field Mapping

| Inspector Field | Normalized Field | Transformation |
|----------------|------------------|----------------|
| `findingArn` | `id` | Direct copy |
| N/A | `scanner` | Set to `"inspector"` |
| `packageVulnerabilityDetails.vulnerablePackages[0].packageManager` | `package_manager` | Lowercase |
| `packageVulnerabilityDetails.vulnerablePackages[0].name` | `package_name` | Direct copy |
| `packageVulnerabilityDetails.vulnerablePackages[0].version` | `current_version` | Direct copy |
| `packageVulnerabilityDetails.vulnerablePackages[0].fixedInVersion` | `fixed_version` | Direct copy or parse from remediation text |
| `severity` | `severity` | Map: `CRITICAL→critical`, `HIGH→high`, `MEDIUM→medium`, `LOW→low` |
| `packageVulnerabilityDetails.relatedVulnerabilities[].id` | `cve` | Extract all CVE-* IDs |
| `packageVulnerabilityDetails.vulnerablePackages[0].filePath` | `manifest_file` | Direct copy |
| `type` | `remediation_type` | Map: `PACKAGE_VULNERABILITY→dependency` |
| `resources[0].id` | `repository` | Direct copy |
| N/A | `branch` | Default: `"main"` |
| N/A | `commit_id` | Default: `"unknown"` |
| Current time | `scan_time` | ISO 8601 format |
| Various | `metadata` | Preserve Inspector-specific fields |

### Severity Mapping

| Inspector Severity | Normalized Severity |
|-------------------|---------------------|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFORMATIONAL` | `low` |
| `UNTRIAGED` | `medium` |

---

## Filtering Examples

### Example 1: Application Dependency (INCLUDED)

**Input:**
```json
{
  "packageVulnerabilityDetails": {
    "vulnerablePackages": [
      {
        "packageManager": "npm",
        "name": "express"
      }
    ]
  }
}
```

**Result:** ✅ **INCLUDED** - npm is an application package manager

---

### Example 2: OS Package (FILTERED OUT)

**Input:**
```json
{
  "packageVulnerabilityDetails": {
    "source": "OS",
    "vulnerablePackages": [
      {
        "packageManager": "apt",
        "name": "libssl1.1"
      }
    ]
  }
}
```

**Result:** ❌ **FILTERED OUT** - apt is an OS package manager AND source is "OS"

---

### Example 3: Maven Dependency (INCLUDED)

**Input:**
```json
{
  "packageVulnerabilityDetails": {
    "vulnerablePackages": [
      {
        "packageManager": "maven",
        "name": "org.springframework:spring-core"
      }
    ]
  }
}
```

**Result:** ✅ **INCLUDED** - maven is an application package manager

---

### Example 4: Python Package (INCLUDED)

**Input:**
```json
{
  "packageVulnerabilityDetails": {
    "vulnerablePackages": [
      {
        "packageManager": "pip",
        "name": "django"
      }
    ]
  }
}
```

**Result:** ✅ **INCLUDED** - pip is an application package manager

---

### Example 5: RPM Package (FILTERED OUT)

**Input:**
```json
{
  "packageVulnerabilityDetails": {
    "vulnerablePackages": [
      {
        "packageManager": "rpm",
        "name": "kernel"
      }
    ]
  }
}
```

**Result:** ❌ **FILTERED OUT** - rpm is an OS package manager

---

## Application vs OS Package Managers

### Application Package Managers (INCLUDED)

These package managers are used for application-level dependencies and are **included** in normalization:

- **npm**: Node.js packages
- **maven**: Java packages (Maven)
- **gradle**: Java packages (Gradle)
- **pip** / **pypi**: Python packages

### OS Package Managers (FILTERED OUT)

These package managers are used for OS-level packages and are **filtered out** from normalization:

- **apt**: Debian/Ubuntu packages
- **yum**: RedHat/CentOS packages
- **apk**: Alpine Linux packages
- **rpm**: RPM-based distributions
- **dpkg**: Debian package manager

### Rationale for Filtering

OS-level vulnerabilities require different remediation strategies:

- **Infrastructure updates**: Base image changes, OS patches
- **Container rebuilds**: Update base container images
- **Platform updates**: Update runtime platform versions

These are outside the scope of application code remediation, which focuses on:

- **Dependency upgrades**: Update package.json, pom.xml, requirements.txt
- **Code fixes**: Fix vulnerable code patterns
- **Import updates**: Update import statements for API changes

---

## Usage Examples

### Processing Inspector Findings

```bash
# Normalize Inspector findings
python .github/scripts/normalize_inspector.py \
  --input aws-inspector-findings.json \
  --output inspector_normalized.json

# Output will contain only application dependencies
# OS packages will be filtered out
```

### Checking Findings Count

```bash
# Count findings in normalized output
jq '.findings | length' inspector_normalized.json

# Expected: Fewer findings than input due to OS package filtering
```

### Viewing Filtered Findings

```bash
# View all findings (including filtered)
jq '.findings[]' aws-inspector-findings.json

# View only normalized findings (application dependencies only)
jq '.findings[]' inspector_normalized.json
```

---

## Related Documentation

- **Design Document**: `.kiro/specs/aws-inspector-integration/design.md`
- **Requirements Document**: `.kiro/specs/aws-inspector-integration/requirements.md`
- **Integration Summary**: `.github/scripts/INTEGRATION_SUMMARY.md`
- **Compatibility Integration**: `.github/scripts/COMPATIBILITY_INTEGRATION.md`
- **Workflow Examples**: `.github/scripts/WORKFLOW_INTEGRATION_EXAMPLES.yml`

---

## Validation

To validate that your normalized output matches the expected schema:

```python
import json
import jsonschema

# Load schema
with open('.github/scripts/normalization/schema.py') as f:
    schema = json.load(f)

# Load normalized output
with open('inspector_normalized.json') as f:
    data = json.load(f)

# Validate each finding
for finding in data['findings']:
    jsonschema.validate(instance=finding, schema=schema)
    print(f"✓ Finding {finding['id']} is valid")
```

---

## Summary

This documentation demonstrates:

1. ✅ **Sample AWS Inspector JSON input** with both application and OS dependencies
2. ✅ **Sample normalized output** showing application dependency filtering
3. ✅ **Sample deduplicated output** showing multi-scanner merge behavior
4. ✅ **Complete field mapping** from Inspector to normalized schema
5. ✅ **Filtering examples** demonstrating inclusion/exclusion logic

All samples are taken directly from the design document and represent the actual data formats used by the normalization framework.
