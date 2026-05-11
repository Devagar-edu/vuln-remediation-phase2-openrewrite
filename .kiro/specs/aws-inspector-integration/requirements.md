# Requirements Document

## Introduction

This document specifies requirements for integrating AWS Inspector vulnerability findings into an existing GitHub Actions-based autonomous vulnerability remediation pipeline. The system currently processes Snyk scan results through normalization, Jira ticket creation, and automated remediation workflows. This integration extends the framework to support AWS Inspector findings in parallel with Snyk, without breaking existing Snyk functionality.

The integration focuses exclusively on application-level code and dependency vulnerabilities (npm, Maven, Gradle, pip) and explicitly excludes OS-level, infrastructure, and runtime platform vulnerabilities.

## Glossary

- **Remediation_Pipeline**: The existing GitHub Actions workflow system that detects, normalizes, tracks, and remediates security vulnerabilities
- **Snyk_Workflow**: The current GitHub Actions workflow that scans code using Snyk and triggers remediation
- **Inspector_Workflow**: The new GitHub Actions workflow that processes AWS Inspector findings and triggers remediation
- **Normalization_Framework**: The system component that transforms scanner-specific vulnerability data into a common schema
- **Scanner_Adapter**: A module that parses vulnerability findings from a specific scanner and converts them to the normalized schema
- **Normalized_Finding**: A vulnerability record in the common schema format used by the remediation engine
- **Remediation_Engine**: The component that executes automated fixes based on normalized findings
- **Application_Dependency**: A software library or package used by application code (npm, Maven, Gradle, pip packages)
- **OS_Package**: A system-level package managed by OS package managers (apt, yum, apk, rpm)
- **Deduplication_Service**: The component that identifies and merges duplicate vulnerability findings from multiple scanners
- **Jira_Integration**: The component that creates and manages Jira tickets for vulnerability tracking

## Requirements

### Requirement 1: AWS Inspector Workflow Creation

**User Story:** As a security engineer, I want a dedicated GitHub Actions workflow for AWS Inspector findings, so that Inspector vulnerabilities are processed independently from Snyk scans.

#### Acceptance Criteria

1. THE Inspector_Workflow SHALL accept AWS Inspector JSON findings as a local file input parameter
2. THE Inspector_Workflow SHALL trigger the same remediation flow as the Snyk_Workflow
3. THE Inspector_Workflow SHALL NOT implement AWS authentication or Inspector API fetching
4. THE Inspector_Workflow SHALL operate independently from the Snyk_Workflow
5. WHEN the Inspector_Workflow completes successfully, THE Remediation_Pipeline SHALL generate a pull request with fixes

### Requirement 2: Generic Normalization Framework

**User Story:** As a developer, I want a scanner-agnostic normalization framework, so that multiple vulnerability scanners can be supported without duplicating remediation logic.

#### Acceptance Criteria

1. THE Normalization_Framework SHALL define a common normalized vulnerability schema
2. THE normalized schema SHALL include source scanner, package manager, package name, current version, fixed version, severity, CVE, manifest file, remediation type, and repository metadata fields
3. THE Normalization_Framework SHALL support pluggable Scanner_Adapter modules
4. WHEN a Scanner_Adapter processes findings, THE Normalization_Framework SHALL produce Normalized_Finding records
5. THE Normalization_Framework SHALL maintain backward compatibility with existing Snyk_Workflow outputs

### Requirement 3: Snyk Scanner Adapter

**User Story:** As a developer, I want the existing Snyk normalization logic refactored into a Scanner_Adapter, so that Snyk processing follows the new pluggable architecture.

#### Acceptance Criteria

1. THE Snyk_Scanner_Adapter SHALL parse Snyk JSON output format
2. THE Snyk_Scanner_Adapter SHALL produce Normalized_Finding records matching the common schema
3. WHEN the Snyk_Scanner_Adapter processes Snyk findings, THE Remediation_Pipeline SHALL produce identical results to the current implementation
4. THE Snyk_Scanner_Adapter SHALL preserve all existing Snyk-specific metadata in the normalized output

### Requirement 4: AWS Inspector Scanner Adapter

**User Story:** As a security engineer, I want an AWS Inspector Scanner_Adapter, so that Inspector findings can be normalized and processed by the remediation pipeline.

#### Acceptance Criteria

1. THE Inspector_Scanner_Adapter SHALL parse AWS Inspector JSON output format
2. THE Inspector_Scanner_Adapter SHALL produce Normalized_Finding records matching the common schema
3. THE Inspector_Scanner_Adapter SHALL extract package manager, package name, current version, fixed version, severity, CVE, and remediation type from Inspector findings
4. WHEN Inspector findings contain repository or service metadata, THE Inspector_Scanner_Adapter SHALL include them in the normalized output

### Requirement 5: Application Dependency Scope Filtering

**User Story:** As a security engineer, I want Inspector findings filtered to application dependencies only, so that OS-level and infrastructure vulnerabilities are excluded from automated remediation.

#### Acceptance Criteria

1. THE Inspector_Scanner_Adapter SHALL process findings where package manager is npm, Maven, Gradle, or pip
2. THE Inspector_Scanner_Adapter SHALL ignore findings where package manager is apt, yum, apk, or rpm
3. THE Inspector_Scanner_Adapter SHALL ignore findings where package source is OS-level
4. THE Inspector_Scanner_Adapter SHALL ignore findings where remediation target is infrastructure or platform
5. WHEN an Inspector finding targets an Application_Dependency, THE Inspector_Scanner_Adapter SHALL include it in normalized output
6. WHEN an Inspector finding targets an OS_Package, THE Inspector_Scanner_Adapter SHALL exclude it from normalized output

### Requirement 6: Scanner-Agnostic Remediation Engine

**User Story:** As a developer, I want the remediation engine to operate on normalized findings only, so that remediation logic is independent of the source scanner.

#### Acceptance Criteria

1. THE Remediation_Engine SHALL accept Normalized_Finding records as input
2. THE Remediation_Engine SHALL determine remediation actions based on remediation_type field, not scanner name
3. THE Remediation_Engine SHALL NOT contain scanner-specific conditional logic
4. WHEN a Normalized_Finding has remediation_type "dependency", THE Remediation_Engine SHALL execute dependency upgrade remediation
5. WHEN a Normalized_Finding has remediation_type "code", THE Remediation_Engine SHALL execute code vulnerability remediation

### Requirement 7: Jira Integration for Inspector Findings

**User Story:** As a security engineer, I want Inspector findings to generate Jira tickets using the same process as Snyk, so that vulnerability tracking is consistent across scanners.

#### Acceptance Criteria

1. THE Jira_Integration SHALL accept Normalized_Finding records from any scanner
2. WHEN Inspector findings are normalized, THE Jira_Integration SHALL create Jira tickets using the existing ticket creation logic
3. THE Jira_Integration SHALL attach the normalized findings JSON to Jira tickets
4. THE Jira_Integration SHALL include scanner source in ticket metadata
5. THE Jira ticket summary SHALL indicate the source scanner (Snyk or Inspector)

### Requirement 8: Vulnerability Deduplication

**User Story:** As a security engineer, I want duplicate vulnerabilities from multiple scanners to be identified, so that the same vulnerability is not remediated multiple times.

#### Acceptance Criteria

1. THE Deduplication_Service SHALL identify duplicate findings using CVE, package name, package version, and repository as matching criteria
2. WHEN multiple scanners report the same vulnerability, THE Deduplication_Service SHALL merge them into a single Normalized_Finding
3. THE merged Normalized_Finding SHALL preserve source scanner information from all contributing findings
4. WHEN a duplicate is detected, THE Deduplication_Service SHALL select the highest severity level among duplicates
5. WHEN a duplicate is detected, THE Deduplication_Service SHALL select the most recent fixed version among duplicates

### Requirement 9: Backward Compatibility with Snyk Workflow

**User Story:** As a developer, I want the existing Snyk workflow to continue working exactly as-is, so that the Inspector integration does not break current functionality.

#### Acceptance Criteria

1. THE Snyk_Workflow SHALL continue to execute without modification to its trigger conditions
2. THE Snyk_Workflow SHALL continue to produce identical outputs after refactoring
3. WHEN the Snyk_Workflow runs, THE Remediation_Pipeline SHALL generate pull requests with the same content as before refactoring
4. THE Snyk_Workflow SHALL NOT require changes to environment variables or secrets
5. WHEN both Snyk_Workflow and Inspector_Workflow run, THE Remediation_Pipeline SHALL process findings from both scanners independently

### Requirement 10: Extensible Scanner Architecture

**User Story:** As a developer, I want the normalization framework designed for extensibility, so that future scanners can be added without major redesign.

#### Acceptance Criteria

1. THE Normalization_Framework SHALL support registration of new Scanner_Adapter modules without modifying core framework code
2. THE normalized schema SHALL accommodate scanner-specific metadata through an extensible metadata field
3. THE Normalization_Framework documentation SHALL include a guide for implementing new Scanner_Adapter modules
4. WHEN a new Scanner_Adapter is registered, THE Normalization_Framework SHALL validate that it implements the required adapter interface
5. THE Normalization_Framework design SHALL support future addition of Trivy, Dependabot, Prisma, Wiz, and Qualys scanners

### Requirement 11: Modular Implementation Structure

**User Story:** As a developer, I want the implementation organized into modular components, so that changes to one scanner do not affect others.

#### Acceptance Criteria

1. THE Scanner_Adapter modules SHALL be implemented in separate files
2. THE Normalization_Framework core SHALL be independent of specific Scanner_Adapter implementations
3. THE Remediation_Engine SHALL be independent of Scanner_Adapter implementations
4. WHEN a Scanner_Adapter is modified, THE Normalization_Framework and Remediation_Engine SHALL NOT require changes
5. THE codebase SHALL organize scanner-specific logic into dedicated modules or packages

### Requirement 12: Inspector Workflow Configuration

**User Story:** As a DevOps engineer, I want the Inspector workflow configurable through environment variables, so that deployment-specific settings can be externalized.

#### Acceptance Criteria

1. THE Inspector_Workflow SHALL accept the Inspector JSON file path as a workflow input parameter
2. THE Inspector_Workflow SHALL reuse existing Jira and GitHub secrets from the Snyk_Workflow
3. THE Inspector_Workflow SHALL support the same branch protection and PR creation settings as the Snyk_Workflow
4. WHERE custom filtering rules are needed, THE Inspector_Workflow SHALL accept them through workflow input parameters
5. THE Inspector_Workflow documentation SHALL specify all required and optional configuration parameters

### Requirement 13: Normalized Schema Validation

**User Story:** As a developer, I want normalized findings validated against the schema, so that invalid data is detected before reaching the remediation engine.

#### Acceptance Criteria

1. THE Normalization_Framework SHALL define a JSON schema for Normalized_Finding records
2. WHEN a Scanner_Adapter produces output, THE Normalization_Framework SHALL validate it against the schema
3. IF a Normalized_Finding fails schema validation, THEN THE Normalization_Framework SHALL log a validation error with details
4. IF a Normalized_Finding fails schema validation, THEN THE Normalization_Framework SHALL exclude it from remediation processing
5. THE validation error log SHALL include the scanner name, finding ID, and validation failure reason

### Requirement 14: Sample Output Documentation

**User Story:** As a developer, I want sample normalized Inspector output documented, so that I can understand the expected data format.

#### Acceptance Criteria

1. THE implementation documentation SHALL include a sample AWS Inspector JSON input
2. THE implementation documentation SHALL include the corresponding normalized output for the sample input
3. THE sample output SHALL demonstrate all fields in the normalized schema
4. THE sample output SHALL demonstrate filtering of OS-level vulnerabilities
5. THE sample output SHALL demonstrate handling of application dependency vulnerabilities

### Requirement 15: Architecture Decision Documentation

**User Story:** As a developer, I want architecture decisions documented in code comments, so that future maintainers understand design rationale.

#### Acceptance Criteria

1. THE Scanner_Adapter interface SHALL include comments explaining the adapter pattern design
2. THE Normalization_Framework core SHALL include comments explaining the pluggable architecture
3. THE filtering logic SHALL include comments explaining the application dependency scope decision
4. THE deduplication logic SHALL include comments explaining the matching criteria selection
5. WHERE scanner-specific workarounds are needed, THE code SHALL include comments explaining the workaround rationale

### Requirement 16: Dependency-Code Compatibility Analysis

**User Story:** As a developer, I want the remediation engine to analyze dependencies between pom.xml changes and code changes, so that dependency upgrades don't break the build due to incompatible API usage.

#### Acceptance Criteria

1. THE Remediation_Engine SHALL analyze the dependency manifest file before applying dependency upgrades
2. THE Remediation_Engine SHALL identify code files that import or use the dependencies being upgraded
3. WHEN a dependency upgrade is planned, THE Remediation_Engine SHALL check for breaking changes between the current version and the fixed version
4. IF breaking changes are detected, THEN THE Remediation_Engine SHALL analyze affected code files for incompatible API usage
5. THE Remediation_Engine SHALL generate code fixes to maintain compatibility with upgraded dependencies
6. THE Remediation_Engine SHALL validate that the build succeeds after applying both dependency upgrades and code fixes
7. IF the build fails after remediation, THEN THE Remediation_Engine SHALL log the build errors and attempt to fix import statements, method signatures, or deprecated API usage
8. THE Remediation_Engine SHALL run the project test suite after applying fixes to verify functionality is preserved
9. WHEN code fixes are required for dependency compatibility, THE pull request description SHALL document both the dependency changes and the corresponding code changes
10. THE Remediation_Engine SHALL prioritize fixes that maintain backward compatibility when multiple fix strategies are available
