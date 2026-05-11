# AWS Inspector Integration - Scripts Documentation

This directory contains the implementation scripts and documentation for the AWS Inspector integration with the autonomous vulnerability remediation pipeline.

## 📁 Directory Structure

```
.github/scripts/
├── normalization/              # Normalization framework
│   ├── framework.py           # Core normalization framework
│   ├── models.py              # Data models (NormalizedFinding, etc.)
│   ├── schema.py              # JSON schema and validation
│   └── adapters/              # Scanner adapters
│       ├── base.py            # Abstract adapter interface
│       ├── snyk_adapter.py    # Snyk scanner adapter
│       └── inspector_adapter.py # AWS Inspector adapter
│
├── normalize_snyk.py          # Snyk normalization script
├── normalize_inspector.py     # Inspector normalization script
├── deduplication.py           # Deduplication service
├── compatibility_analyzer.py  # Compatibility analyzer
├── run_compatibility_analysis.py # Compatibility analysis script
│
├── create_jira.py             # Jira integration
├── fix_dependencies.py        # Dependency remediation
├── fix_code_vulnerabilities.py # Code remediation
├── fix_build_errors.py        # Build error recovery
└── fix_imports.py             # Import fix utility
```

## 📚 Documentation Index

### Core Documentation

1. **[Schema Compatibility Verification](SCHEMA_COMPATIBILITY_VERIFICATION.md)** ⭐
   - **MOST IMPORTANT** - Comprehensive verification that Snyk and Inspector use the same schema
   - Proves 100% compatibility between scanners
   - Field-by-field comparison
   - Remediation pipeline compatibility analysis

2. **[Static Mapping Validation](STATIC_MAPPING_VALIDATION.md)**
   - Validates all static mappings (package managers, severity levels, file extensions)
   - Risk assessment for each mapping
   - No critical issues found

3. **[Inspector Workflow Correction Summary](INSPECTOR_WORKFLOW_CORRECTION_SUMMARY.md)**
   - Documents the correction to match Snyk workflow pattern
   - Explains why Inspector workflow should NOT trigger remediation directly
   - Jira-centric workflow pattern

### Feature Documentation

4. **[Compatibility Integration](COMPATIBILITY_INTEGRATION.md)**
   - Documents the compatibility analyzer feature
   - Dependency-code compatibility analysis
   - Breaking change detection
   - Code fix generation

5. **[Build Validation](BUILD_VALIDATION_README.md)**
   - Documents build validation feature
   - Build error recovery
   - Test execution

6. **[Sample Data Documentation](SAMPLE_DATA_DOCUMENTATION.md)**
   - Sample Inspector JSON input
   - Sample normalized output
   - Sample deduplicated output

7. **[PR Template for Compatibility](PR_TEMPLATE_COMPATIBILITY.md)**
   - Pull request template for compatibility changes
   - Documents dependency upgrades and code fixes

### Adapter Documentation

8. **[Snyk Adapter README](normalization/adapters/SNYK_ADAPTER_README.md)**
   - Snyk adapter implementation details
   - Parsing logic for dependency and code vulnerabilities

9. **[Inspector Adapter README](normalization/adapters/INSPECTOR_ADAPTER_README.md)**
   - Inspector adapter implementation details
   - Application dependency filtering logic

## 🚀 Quick Start

### Normalize Snyk Findings

```bash
python .github/scripts/normalize_snyk.py \
  --deps snyk-deps.json \
  --code snyk-code.json \
  --output vuln_report.json
```

### Normalize Inspector Findings

```bash
python .github/scripts/normalize_inspector.py \
  --input inspector.json \
  --output inspector_normalized.json
```

### Run Compatibility Analysis

```bash
python .github/scripts/run_compatibility_analysis.py \
  --findings normalized-findings.json \
  --manifest pom.xml \
  --source-dir src/main/java \
  --output compatibility-report.json
```

## 🔑 Key Concepts

### Normalization Framework

The normalization framework provides a scanner-agnostic way to process vulnerability findings:

1. **Scanner Adapters** - Parse scanner-specific formats
2. **Normalized Schema** - Common data model for all scanners
3. **Validation** - JSON schema validation
4. **Deduplication** - Merge duplicate findings from multiple scanners

### Schema Compatibility

**Critical**: Both Snyk and Inspector produce **identical normalized output** that is fully compatible with the remediation pipeline. See [Schema Compatibility Verification](SCHEMA_COMPATIBILITY_VERIFICATION.md) for proof.

### Workflow Pattern

Both Snyk and Inspector workflows follow the same pattern:
1. Scan/Normalize findings
2. Create Jira ticket
3. **STOP** (no direct remediation trigger)
4. Remediation triggered separately (from Jira status change)

## 📖 Architecture Decisions

### ADR-001: Pluggable Adapter Pattern
- Use adapter pattern for scanner-specific parsing
- Enables adding new scanners without modifying core framework

### ADR-002: Application Dependency Filtering
- Filter Inspector findings to application dependencies only
- Exclude OS-level packages (apt, yum, apk, rpm)

### ADR-003: CVE-Based Deduplication
- Use CVE + package name + version as deduplication key
- Merge duplicate findings from multiple scanners

### ADR-004: Backward Compatibility
- Maintain 100% compatibility with existing Snyk workflow
- Snyk adapter produces identical output to legacy normalize.py

### ADR-005: Dependency-Code Compatibility Analysis
- Analyze code for breaking changes when upgrading dependencies
- Generate code fixes to maintain compatibility

## 🧪 Testing

### Unit Tests
```bash
python -m pytest .github/scripts/normalization/adapters/
```

### Integration Tests
```bash
python .github/scripts/test_integration_fix_dependencies.py
```

### Performance Tests
```bash
python .github/scripts/test_performance.py
```

## 🔗 Related Documentation

- **Design Document**: `.kiro/specs/aws-inspector-integration/design.md`
- **Requirements Document**: `.kiro/specs/aws-inspector-integration/requirements.md`
- **Tasks Document**: `.kiro/specs/aws-inspector-integration/tasks.md`

## 📝 Notes

- All scripts use Python 3.9+
- Dependencies listed in `requirements.txt`
- Logging configured at INFO level by default
- All paths are relative to workspace root

---

**Last Updated**: 2026-05-12  
**Version**: 1.0.0  
**Status**: Production Ready ✅
