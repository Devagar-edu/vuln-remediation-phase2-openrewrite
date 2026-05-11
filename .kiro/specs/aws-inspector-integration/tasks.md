# Implementation Plan: AWS Inspector Integration

## Overview

This implementation plan extends the existing GitHub Actions-based autonomous vulnerability remediation pipeline to support AWS Inspector findings alongside Snyk. The implementation follows a phased approach to ensure backward compatibility and minimize risk:

1. **Phase 1: Framework Implementation** - Create the normalization framework with Snyk adapter (no breaking changes)
2. **Phase 2: Inspector Integration** - Add Inspector adapter, deduplication, and workflow
3. **Phase 3: Compatibility Analyzer** - Implement dependency-code compatibility analysis
4. **Phase 4: Integration and Testing** - Update existing scripts and perform end-to-end validation

The implementation uses Python and maintains 100% backward compatibility with the existing Snyk workflow.

## Tasks

### Phase 1: Framework Implementation (No Breaking Changes)

- [x] 1. Create normalization framework core infrastructure
  - [x] 1.1 Create normalization module structure
    - Create `.github/scripts/normalization/` directory
    - Create `__init__.py`, `framework.py`, `schema.py`, `models.py` files
    - Create `.github/scripts/normalization/adapters/` subdirectory with `__init__.py`, `base.py`
    - _Requirements: 2.1, 11.1, 11.2_

  - [x] 1.2 Implement NormalizedFinding data model
    - Define `NormalizedFinding` dataclass in `models.py` with all required fields (id, scanner, package_manager, package_name, current_version, fixed_version, severity, cve, manifest_file, remediation_type, repository, branch, commit_id, scan_time, metadata)
    - Implement `to_dict()` method for JSON serialization
    - Add type hints for all fields
    - _Requirements: 2.2, 17.1_

  - [x] 1.3 Implement JSON schema definition and validation
    - Define JSON schema in `schema.py` matching the design document specification
    - Implement schema loading function
    - Implement validation function using jsonschema library
    - Add detailed error logging for validation failures
    - _Requirements: 2.2, 13.1, 13.2, 13.3_

  - [x] 1.4 Implement ScannerAdapter base interface
    - Define abstract `ScannerAdapter` class in `adapters/base.py`
    - Define abstract methods: `parse()`, `get_scanner_name()`, `get_scanner_version()`
    - Add comprehensive docstrings explaining the adapter pattern
    - _Requirements: 2.3, 10.1, 15.1_

  - [x] 1.5 Implement NormalizationFramework core class
    - Implement `NormalizationFramework` class in `framework.py`
    - Implement adapter registration with validation
    - Implement `normalize()` method with schema validation
    - Implement error handling for invalid findings (log and exclude)
    - Add structured logging with scanner name, finding ID, and error details
    - _Requirements: 2.1, 2.3, 2.4, 10.4, 13.4, 13.5, 15.2_

  - [ ]* 1.6 Write unit tests for framework core
    - Test adapter registration with valid and invalid adapters
    - Test schema validation with valid and invalid findings
    - Test error logging for validation failures
    - Test invalid finding exclusion from output
    - _Requirements: 2.3, 13.2, 13.3, 13.4, 13.5_

- [x] 2. Implement Snyk adapter (refactor existing normalize.py)
  - [x] 2.1 Create SnykAdapter class
    - Create `snyk_adapter.py` in `adapters/` directory
    - Implement `SnykAdapter` class extending `ScannerAdapter`
    - Implement `get_scanner_name()` returning "snyk"
    - Implement `get_scanner_version()` method
    - _Requirements: 3.1, 11.1_

  - [x] 2.2 Refactor dependency vulnerability parsing
    - Extract `parse_dependency_scan()` logic from existing `normalize.py`
    - Implement `_parse_dependency_vulns()` method in SnykAdapter
    - Map Snyk dependency fields to NormalizedFinding schema
    - Preserve all Snyk-specific metadata in metadata field
    - Handle version extraction using existing `extract_version()` logic
    - _Requirements: 3.1, 3.2, 3.4_

  - [x] 2.3 Refactor code vulnerability parsing
    - Extract `parse_code_scan()` logic from existing `normalize.py`
    - Implement `_parse_code_vulns()` method in SnykAdapter
    - Map Snyk code vulnerability fields to NormalizedFinding schema
    - Preserve all Snyk-specific metadata (rule_id, rule_name, CWE, tags)
    - _Requirements: 3.1, 3.2, 3.4_

  - [x] 2.4 Implement main parse() method
    - Implement `parse()` method that calls both `_parse_dependency_vulns()` and `_parse_code_vulns()`
    - Combine results into single list of NormalizedFinding objects
    - Add error handling for malformed Snyk JSON
    - _Requirements: 3.1, 3.2_

  - [ ]* 2.5 Write unit tests for Snyk adapter
    - Test dependency vulnerability parsing with sample Snyk JSON
    - Test code vulnerability parsing with sample Snyk JSON
    - Test metadata preservation for all Snyk-specific fields
    - Test error handling for malformed input
    - _Requirements: 3.2, 3.4_

  - [ ]* 2.6 Write property test for Snyk backward compatibility
    - **Property 3: Snyk Backward Compatibility**
    - **Validates: Requirements 2.5, 3.3, 9.2, 9.3**
    - Load 100 real Snyk scan results from production or fixtures
    - Process through both old normalize.py and new SnykAdapter
    - Verify outputs are identical (field-by-field comparison)
    - _Requirements: 2.5, 3.3, 9.2, 9.3_

- [x] 3. Checkpoint - Verify backward compatibility
  - Run all unit tests and property tests
  - Verify Snyk adapter produces identical output to existing normalize.py
  - Ensure all tests pass before proceeding to Phase 2

### Phase 2: Inspector Integration

- [x] 4. Implement AWS Inspector adapter
  - [ ] 4.1 Create InspectorAdapter class structure
    - Create `inspector_adapter.py` in `adapters/` directory
    - Implement `InspectorAdapter` class extending `ScannerAdapter`
    - Define `APP_PACKAGE_MANAGERS` and `OS_PACKAGE_MANAGERS` constants
    - Implement `get_scanner_name()` returning "inspector"
    - Implement `get_scanner_version()` method
    - _Requirements: 4.1, 5.1, 5.2_

  - [ ] 4.2 Implement application dependency filtering
    - Implement `_is_application_dependency()` method
    - Check packageManager field against APP_PACKAGE_MANAGERS whitelist
    - Check packageManager field against OS_PACKAGE_MANAGERS blacklist
    - Check source field for "OS", "OPERATING_SYSTEM", "SYSTEM" values
    - Return False for uncertain cases (fail-safe default)
    - Add detailed comments explaining filtering rationale
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 15.3_

  - [ ] 4.3 Implement Inspector finding normalization
    - Implement `_normalize_finding()` method
    - Extract package manager, name, version from vulnerablePackages array
    - Map Inspector severity to normalized severity (CRITICAL→critical, HIGH→high, etc.)
    - Extract CVE identifiers from relatedVulnerabilities array
    - Extract repository from resources array
    - Preserve all Inspector-specific metadata (findingArn, title, description, timestamps, CVSS)
    - _Requirements: 4.2, 4.3, 4.4_

  - [ ] 4.4 Implement fixed version extraction
    - Implement `_extract_fixed_version()` method
    - Strategy 1: Check fixedInVersion field in vulnerablePackages
    - Strategy 2: Parse remediation.recommendation.text with regex
    - Return "unknown" if no fix version found
    - _Requirements: 4.3_

  - [ ] 4.5 Implement helper methods
    - Implement `_extract_cves()` to extract CVE IDs from relatedVulnerabilities
    - Implement `_map_severity()` to map Inspector severity levels
    - Implement `_determine_remediation_type()` to classify as dependency or code
    - _Requirements: 4.3_

  - [ ] 4.6 Implement main parse() method
    - Implement `parse()` method iterating over findings array
    - Apply `_is_application_dependency()` filter
    - Call `_normalize_finding()` for filtered findings
    - Add error handling for malformed Inspector JSON
    - Log filtered-out findings for audit trail
    - _Requirements: 4.1, 4.2, 5.1, 5.2_

  - [ ]* 4.7 Write unit tests for Inspector adapter
    - Test application dependency inclusion (npm, maven, gradle, pip)
    - Test OS package exclusion (apt, yum, apk, rpm)
    - Test field extraction completeness
    - Test metadata preservation
    - Test error handling for malformed input
    - _Requirements: 4.1, 4.3, 4.4, 5.1, 5.2, 5.5, 5.6_

  - [ ]* 4.8 Write property test for Inspector parsing robustness
    - **Property 5: Inspector Parsing Robustness**
    - **Validates: Requirements 4.1**
    - Generate valid Inspector JSON structures with hypothesis
    - Verify adapter parses without exceptions
    - _Requirements: 4.1_

  - [ ]* 4.9 Write property test for application dependency filtering
    - **Property 8: Application Dependency Inclusion**
    - **Validates: Requirements 5.1, 5.5**
    - Generate Inspector findings with application package managers
    - Verify findings are included in output
    - **Property 9: OS Package Exclusion**
    - **Validates: Requirements 5.2, 5.3, 5.4, 5.6**
    - Generate Inspector findings with OS package managers
    - Verify findings are excluded from output
    - _Requirements: 5.1, 5.2, 5.5, 5.6_

- [x] 5. Implement deduplication service
  - [x] 5.1 Create DeduplicationService class
    - Create `deduplication.py` in `.github/scripts/` directory
    - Implement `DeduplicationService` class
    - Add docstrings explaining CVE-based deduplication strategy
    - _Requirements: 8.1, 15.4_

  - [x] 5.2 Implement deduplication key generation
    - Implement `_group_by_key()` method
    - Use tuple of (CVE, package_name, current_version, repository) as key
    - Handle findings with no CVE (use "NO_CVE" placeholder)
    - Return dictionary mapping keys to lists of findings
    - _Requirements: 8.1_

  - [x] 5.3 Implement finding merge logic
    - Implement `_merge_findings()` method
    - Combine scanner names into comma-separated string
    - Select highest severity using severity_order mapping
    - Select most recent fixed version using packaging.version
    - Union all CVE lists
    - Merge all metadata dictionaries
    - Add deduplicated_from and source_scanners to metadata
    - _Requirements: 8.2, 8.3, 8.4, 8.5_

  - [x] 5.4 Implement main deduplicate() method
    - Implement `deduplicate()` method
    - Group findings by deduplication key
    - For single-finding groups, return as-is
    - For multi-finding groups, call `_merge_findings()`
    - Add error handling with fallback to string comparison for invalid versions
    - _Requirements: 8.1, 8.2_

  - [ ]* 5.5 Write unit tests for deduplication
    - Test single finding (no deduplication)
    - Test duplicate detection with matching CVE+package+version
    - Test merge behavior (scanner combination, severity selection, version selection)
    - Test handling of missing CVEs
    - Test error handling for invalid versions
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

  - [ ]* 5.6 Write property test for deduplication behavior
    - **Property 14: Deduplication Key Matching**
    - **Validates: Requirements 8.1**
    - Generate pairs of findings with identical deduplication keys
    - Verify they are identified as duplicates
    - **Property 15: Deduplication Merge Behavior**
    - **Validates: Requirements 8.2, 8.3, 8.4, 8.5**
    - Generate sets of duplicate findings with varying severities and versions
    - Verify merged finding preserves all sources, selects highest severity, selects most recent version
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 6. Create Inspector workflow
  - [x] 6.1 Create Inspector workflow YAML file
    - Create `.github/workflows/inspector_scan.yml`
    - Define workflow_dispatch trigger with inspector_json_file input parameter
    - Set required permissions (contents: write, pull-requests: write, issues: write, models: read)
    - _Requirements: 1.1, 1.2, 12.1_

  - [x] 6.2 Add workflow steps for Inspector processing
    - Add checkout step
    - Add dependency installation step (pip install -r requirements.txt)
    - Add JSON file validation step
    - Add normalization step calling normalize_inspector.py script
    - Add vulnerability count check step
    - Add artifact upload step for normalized report
    - _Requirements: 1.1, 1.2, 12.1_

  - [x] 6.3 Add Jira integration step
    - Add Jira ticket creation step using existing create_jira.py
    - Reuse existing Jira secrets (JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN)
    - Only run if vulnerabilities found
    - _Requirements: 1.2, 7.1, 7.2, 12.2_

  - [x] 6.4 ~~Add remediation trigger step~~ **CORRECTED: No direct remediation trigger**
    - ~~Add repository_dispatch step to trigger Remediation.yml workflow~~
    - ~~Pass Jira issue key and scanner name in client_payload~~
    - ~~Only run if vulnerabilities found~~
    - **CORRECTION**: Inspector workflow should NOT trigger remediation directly
    - **REASON**: Must match Snyk workflow pattern (Jira-only, no direct remediation trigger)
    - **IMPLEMENTATION**: Removed repository_dispatch step to maintain consistency with Snyk workflow
    - _Requirements: 1.2 (correctly interpreted as "same pattern", not "same trigger mechanism")_

  - [x] 6.5 Create normalize_inspector.py script
    - Create `.github/scripts/normalize_inspector.py`
    - Accept --input and --output command-line arguments
    - Load Inspector JSON file
    - Initialize NormalizationFramework and register InspectorAdapter
    - Call normalize() and deduplicate()
    - Write output JSON with scan_metadata and findings
    - Add error handling and logging
    - _Requirements: 1.1, 4.1, 8.1_

  - [ ]* 6.6 Write integration test for Inspector workflow
    - Create sample Inspector JSON with application and OS dependencies
    - Run workflow end-to-end
    - Verify normalized output contains only application dependencies
    - Verify Jira ticket created (if Jira available)
    - _Requirements: 1.1, 1.2, 1.5, 5.1, 5.2_

- [x] 7. Checkpoint - Verify Inspector integration
  - Run all unit tests and property tests for Inspector adapter and deduplication
  - Manually test Inspector workflow with sample JSON file
  - Verify OS packages are filtered out
  - Verify Jira ticket creation works
  - Ensure all tests pass before proceeding to Phase 3

### Phase 3: Compatibility Analyzer

- [x] 8. Implement compatibility analyzer core
  - [x] 8.1 Create CompatibilityAnalyzer class structure
    - Create `compatibility_analyzer.py` in `.github/scripts/` directory
    - Implement `CompatibilityAnalyzer` class
    - Define DependencyChange, BreakingChange, CodeFix dataclasses in models.py
    - Add docstrings explaining dependency-code compatibility analysis
    - _Requirements: 16.1, 16.2, 16.3, 15.5_

  - [x] 8.2 Implement affected file identification
    - Implement `_find_affected_files()` method
    - Walk source directory tree to find source files
    - Implement `_get_import_pattern()` to generate package-specific import regex
    - Implement `_is_source_file()` to filter by extension (.java, .py, .js, .ts)
    - Implement `_file_imports_package()` to check if file imports the dependency
    - Return list of file paths that import the dependency
    - _Requirements: 16.2_

  - [x] 8.3 Implement breaking change detection
    - Implement `_check_breaking_changes()` method
    - Query package registry (Maven Central, npm, PyPI) for changelog
    - Parse CHANGELOG.md or release notes from registry
    - Search for keywords: "breaking", "removed", "deprecated", "renamed"
    - Use AI to analyze changelog text for breaking changes
    - Return list of BreakingChange objects
    - _Requirements: 16.3_

  - [x] 8.4 Implement code fix generation
    - Implement `_generate_fixes()` method
    - Read source file content
    - For each breaking change, identify affected code locations
    - Use AI (similar to fix_code_vulnerabilities.py) to generate fixes
    - Return list of CodeFix objects with file path, original code, fixed code, and reason
    - _Requirements: 16.4, 16.5_

  - [x] 8.5 Implement main analyze() method
    - Implement `analyze()` method accepting dependency changes and codebase path
    - For each dependency change, call `_find_affected_files()`
    - Call `_check_breaking_changes()` for each dependency
    - If breaking changes found, call `_generate_fixes()` for each affected file
    - Return list of all CodeFix objects
    - Add error handling and logging
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5_

  - [ ]* 8.6 Write unit tests for compatibility analyzer
    - Test affected file identification with sample project structure
    - Test breaking change detection with sample changelogs
    - Test code fix generation with sample breaking changes
    - Test error handling for missing changelogs
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5_

  - [ ]* 8.7 Write property test for compatibility analysis
    - **Property 20: Compatibility Analysis Execution**
    - **Validates: Requirements 16.1, 16.2, 16.3**
    - Generate dependency upgrades with various package managers
    - Verify analyzer identifies affected files and checks for breaking changes
    - _Requirements: 16.1, 16.2, 16.3_

- [x] 9. Implement build validation and error recovery
  - [x] 9.1 Implement build validation
    - Implement `validate_build()` method in CompatibilityAnalyzer
    - Run project build command (mvn compile, npm run build, etc.)
    - Capture build output and parse for errors
    - Return BuildResult with success status and error list
    - _Requirements: 16.6_

  - [x] 9.2 Implement build error recovery
    - Implement `_attempt_error_recovery()` method
    - Parse build error messages for common patterns (missing imports, API changes)
    - Generate automated fixes for recoverable errors
    - Apply fixes and return success status
    - Retry build up to max_retries times
    - _Requirements: 16.7_

  - [x] 9.3 Implement test execution
    - Implement `run_tests()` method
    - Run project test suite (mvn test, npm test, pytest, etc.)
    - Capture test output and parse for failures
    - Return TestResult with success status and failure list
    - _Requirements: 16.8_

  - [ ]* 9.4 Write unit tests for build validation
    - Test build validation with successful build
    - Test build validation with failed build
    - Test error recovery with recoverable errors
    - Test retry logic with max_retries
    - Test test execution with passing and failing tests
    - _Requirements: 16.6, 16.7, 16.8_

  - [ ]* 9.5 Write property test for build validation
    - **Property 23: Build and Test Validation**
    - **Validates: Requirements 16.6, 16.7, 16.8**
    - Generate various remediation scenarios
    - Verify build and tests are validated with error recovery on failure
    - _Requirements: 16.6, 16.7, 16.8_

- [x] 10. Integrate compatibility analyzer with remediation engine
  - [x] 10.1 Update fix_dependencies.py to use compatibility analyzer
    - Import CompatibilityAnalyzer class
    - Before applying dependency upgrades, call analyzer.analyze()
    - Extract DependencyChange objects from normalized findings
    - Apply code fixes returned by analyzer
    - Update pom.xml/package.json with dependency upgrades
    - _Requirements: 16.1, 16.5, 16.6_

  - [x] 10.2 Update Remediation.yml workflow
    - Add compatibility analysis step before dependency fixes
    - Call compatibility_analyzer.py script with findings, manifest, and source directory
    - Pass compatibility report to fix_dependencies.py
    - Add build validation step after fixes
    - Add test execution step after build validation
    - _Requirements: 16.6, 16.7, 16.8_

  - [x] 10.3 Update pull request documentation
    - Modify PR creation step to include compatibility analysis results
    - Document dependency changes in PR description
    - Document code changes required for compatibility
    - Include build and test validation results
    - _Requirements: 16.9_

  - [ ]* 10.4 Write integration test for compatibility analyzer
    - Create sample project with dependency requiring code changes
    - Run remediation workflow end-to-end
    - Verify dependency upgraded
    - Verify code fixes applied
    - Verify build succeeds
    - Verify tests pass
    - _Requirements: 16.1, 16.5, 16.6, 16.7, 16.8_

- [ ] 11. Checkpoint - Verify compatibility analyzer integration
  - Run all unit tests and property tests for compatibility analyzer
  - Manually test remediation workflow with dependency requiring code changes
  - Verify code fixes are generated and applied
  - Verify build succeeds after remediation
  - Ensure all tests pass before proceeding to Phase 4

### Phase 4: Integration and Testing

- [ ] 12. Update existing scripts to use normalized schema
  - [x] 12.1 Update create_jira.py to accept normalized schema
    - Modify `load_scan()` to handle both old and new schema formats
    - Update `build_summary()` to extract counts from normalized schema
    - Ensure backward compatibility with existing Snyk workflow
    - Test with both Snyk and Inspector normalized outputs
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 9.4_

  - [x] 12.2 Update fix_dependencies.py to accept normalized schema
    - Modify script to read normalized findings format
    - Extract package_name, current_version, fixed_version from normalized schema
    - Maintain existing Maven/npm dependency update logic
    - Test with both Snyk and Inspector normalized outputs
    - _Requirements: 6.1, 6.2, 9.4_

  - [x] 12.3 Update fix_code_vulnerabilities.py to accept normalized schema
    - Modify script to read normalized findings format
    - Extract file paths, line numbers, and vulnerability details from normalized schema
    - Maintain existing AI-based code fix logic
    - Test with both Snyk and Inspector normalized outputs
    - _Requirements: 6.1, 6.2, 9.4_

  - [x] 12.4 Update Snyk workflow to use new framework
    - Modify vuln_scan.yml to call new normalization framework
    - Replace normalize.py call with framework-based normalization
    - Register SnykAdapter with framework
    - Ensure output format matches existing format for backward compatibility
    - _Requirements: 2.5, 9.1, 9.2, 9.3, 9.4, 9.5_

  - [ ]* 12.5 Write integration test for updated Snyk workflow
    - Run updated Snyk workflow end-to-end
    - Verify output matches original workflow output
    - Verify Jira ticket creation works
    - Verify remediation workflow triggers correctly
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [ ] 13. End-to-end testing and validation
  - [ ]* 13.1 Write integration test for multi-scanner scenario
    - Run both Snyk and Inspector workflows in parallel
    - Verify findings are deduplicated correctly
    - Verify merged findings preserve all scanner sources
    - Verify single Jira ticket created for duplicates
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 9.5_

  - [ ]* 13.2 Write property tests for scanner-agnostic remediation
    - **Property 11: Scanner-Agnostic Remediation Routing**
    - **Validates: Requirements 6.2, 6.4, 6.5**
    - Generate findings with same remediation_type but different scanners
    - Verify remediation engine triggers same action regardless of scanner
    - _Requirements: 6.2, 6.4, 6.5_

  - [ ]* 13.3 Write property tests for Jira integration
    - **Property 12: Jira Integration Scanner Agnosticism**
    - **Validates: Requirements 7.1**
    - Generate findings from various scanners
    - Verify Jira integration creates tickets for all scanners
    - **Property 13: Jira Ticket Completeness**
    - **Validates: Requirements 7.3, 7.4, 7.5**
    - Verify tickets contain JSON attachment, scanner metadata, and scanner in summary
    - _Requirements: 7.1, 7.3, 7.4, 7.5_

  - [ ]* 13.4 Write property tests for schema validation
    - **Property 2: Schema Validation Universality**
    - **Validates: Requirements 2.4, 3.2, 4.2, 13.2, 13.3, 13.4**
    - Generate valid and invalid normalized findings
    - Verify valid findings pass validation
    - Verify invalid findings are excluded with logged errors
    - **Property 18: Validation Error Logging**
    - **Validates: Requirements 13.5**
    - Verify error logs contain scanner name, finding ID, and failure reason
    - **Property 19: Invalid Finding Exclusion**
    - **Validates: Requirements 13.4**
    - Verify invalid findings are not passed to remediation or Jira
    - _Requirements: 2.4, 3.2, 4.2, 13.2, 13.3, 13.4, 13.5_

  - [ ]* 13.5 Write property tests for extensibility
    - **Property 1: Scanner Adapter Registration**
    - **Validates: Requirements 2.3, 10.1, 10.4**
    - Create mock scanner adapters
    - Verify registration and usage without errors
    - **Property 17: Schema Extensibility**
    - **Validates: Requirements 10.2**
    - Generate findings with arbitrary scanner-specific metadata
    - Verify metadata is stored without validation errors
    - _Requirements: 2.3, 10.1, 10.2, 10.4_

  - [x] 13.6 Performance testing
    - Test normalization framework with 1000+ findings
    - Test deduplication with 500+ duplicate findings
    - Measure workflow execution time (target: <10 minutes)
    - Identify and optimize bottlenecks
    - _Requirements: 2.1, 8.1_

  - [x] 13.7 Create sample data documentation
    - Document sample AWS Inspector JSON input (from design document)
    - Document sample normalized output (from design document)
    - Document sample deduplicated output (from design document)
    - Add samples to implementation documentation
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

- [ ] 14. Documentation and cleanup
  - [x] 14.1 Create implementation documentation
    - Document file structure and module organization
    - Document normalization framework usage
    - Document how to add new scanner adapters
    - Document compatibility analyzer usage
    - Include architecture decision rationale in code comments
    - _Requirements: 10.3, 15.1, 15.2, 15.3, 15.4, 15.5_

  - [ ] 14.2 Update README with Inspector workflow instructions
    - Document how to trigger Inspector workflow
    - Document required input format (Inspector JSON)
    - Document configuration parameters
    - Document secrets and environment variables
    - _Requirements: 12.3, 12.4, 12.5_

  - [ ] 14.3 Create migration guide
    - Document phased rollout plan
    - Document backward compatibility verification steps
    - Document rollback procedure
    - Document monitoring and alerting setup
    - _Requirements: 9.1, 9.2, 9.3_

  - [ ] 14.4 Deprecate old normalize.py script
    - Add deprecation warning to normalize.py
    - Update all references to use new framework
    - Remove normalize.py after verification period
    - _Requirements: 9.1, 9.4_

  - [ ] 14.5 Add monitoring and alerting
    - Add metrics for normalization success rate
    - Add metrics for schema validation failure rate
    - Add metrics for deduplication rate
    - Add metrics for remediation success rate
    - Add metrics for build success rate
    - Add alerts for failure rate thresholds
    - _Requirements: 16.6, 16.7_

- [ ] 15. Final checkpoint - Ensure all tests pass
  - Run complete test suite (unit + property + integration)
  - Verify all 25 correctness properties pass
  - Verify backward compatibility with existing Snyk workflow
  - Verify Inspector workflow works end-to-end
  - Verify compatibility analyzer works with real dependency upgrades
  - Verify documentation is complete and accurate

## Notes

- Tasks marked with `*` are optional testing tasks and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at phase boundaries
- Property tests validate universal correctness properties across all inputs
- Unit tests validate specific examples and edge cases
- Integration tests validate end-to-end workflows
- The implementation maintains 100% backward compatibility with existing Snyk workflow
- Python is used for all implementation (matching the design document)
- The phased approach minimizes risk and allows for gradual rollout
