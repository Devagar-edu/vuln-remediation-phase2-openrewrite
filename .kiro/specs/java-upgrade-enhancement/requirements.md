# Requirements Document: Java Upgrade Enhancement

## Introduction

This document specifies requirements for enhancing the existing AI-powered security remediation workflow with intelligent Java version upgrade capabilities. The current system fixes dependency vulnerabilities within the same Java version but cannot handle vulnerabilities that require a Java version upgrade. This enhancement adds decision logic to determine when Java upgrades are needed and integrates OpenRewrite-based migration workflows to perform those upgrades safely.

## Glossary

- **Remediation_Workflow**: The GitHub Actions workflow that processes vulnerability findings, updates dependencies, fixes build errors, and creates pull requests
- **Vulnerability_Analyzer**: The AI-powered component that analyzes vulnerability findings and determines remediation strategies
- **Java_Upgrade_Analyzer**: The component (analyze_java_upgrade.py) that determines if Java version upgrade is required
- **OpenRewrite**: An automated refactoring tool that performs Java version migrations and code transformations
- **Recipe**: An OpenRewrite configuration file that specifies code transformations to perform
- **Dependency_Fixer**: The component (fix_dependencies.py) that updates dependency versions in pom.xml
- **Build_Error_Fixer**: The AI-powered component (fix_build_errors.py) that fixes compilation errors after dependency or Java version changes
- **Decision_Engine**: The logic that determines whether to fix vulnerabilities in current Java version or trigger Java upgrade
- **Normalized_Findings**: The standardized JSON format containing vulnerability data from Snyk or AWS Inspector
- **Maven_Central**: The public repository for Java dependencies
- **Spring_Boot**: The Java application framework used by the target project
- **POM**: The Maven Project Object Model file (pom.xml) that defines project dependencies and build configuration

## Requirements

### Requirement 1: Intelligent Upgrade Decision Logic

**User Story:** As a security engineer, I want the system to automatically determine whether vulnerabilities can be fixed in the current Java version or require a Java upgrade, so that I don't waste time attempting impossible fixes.

#### Acceptance Criteria

1. WHEN the Remediation_Workflow receives Normalized_Findings, THE Decision_Engine SHALL analyze whether vulnerabilities can be fixed in the current Java version
2. THE Decision_Engine SHALL invoke the Java_Upgrade_Analyzer with the Normalized_Findings, pom.xml, and source directory as inputs
3. THE Java_Upgrade_Analyzer SHALL return a recommendation of "STAY_JAVA_8", "UPGRADE_JAVA_11", or "UPGRADE_JAVA_17"
4. IF the recommendation is "STAY_JAVA_8", THEN THE Remediation_Workflow SHALL proceed with the existing dependency update approach using Dependency_Fixer
5. IF the recommendation is "UPGRADE_JAVA_11" or "UPGRADE_JAVA_17", THEN THE Remediation_Workflow SHALL trigger the OpenRewrite-based Java upgrade workflow. 
6. THE Decision_Engine SHALL log the decision rationale including vulnerability count, severity, and migration complexity
7. THE Decision_Engine SHALL save the recommendation to a file named "java_upgrade_recommendation.json" for audit purposes

### Requirement 2: OpenRewrite Recipe Generation

**User Story:** As a developer, I want the system to automatically generate OpenRewrite recipes for Java version migrations, so that the upgrade process is consistent and repeatable.

#### Acceptance Criteria

1. WHEN a Java upgrade is required, THE Recipe_Generator SHALL create an OpenRewrite recipe file for the target Java version
2. WHERE the target is Java 11, THE Recipe_Generator SHALL include the "org.openrewrite.java.migrate.Java8toJava11" recipe
3. WHERE the target is Java 17, THE Recipe_Generator SHALL include the "org.openrewrite.java.migrate.UpgradeToJava17" recipe
4. THE Recipe_Generator SHALL include Spring Boot upgrade recipes when Spring Boot version upgrade is required
5. THE Recipe_Generator SHALL include the "org.openrewrite.java.migrate.jakarta.JavaxMigrationToJakarta" recipe when migrating to Java 17
6. THE Recipe SHALL be saved to a file named "rewrite.yml" in the project root directory
7. THE Recipe_Generator SHALL validate that the recipe file is syntactically correct YAML before proceeding

### Requirement 3: OpenRewrite Execution

**User Story:** As a security engineer, I want the system to execute OpenRewrite recipes to perform Java version migrations, so that code transformations are applied automatically and consistently.

#### Acceptance Criteria

1. WHEN a Recipe file exists, THE OpenRewrite_Executor SHALL invoke the Maven OpenRewrite plugin to apply the recipe
2. THE OpenRewrite_Executor SHALL execute the command "mvn org.openrewrite.maven:rewrite-maven-plugin:run"
3. THE OpenRewrite_Executor SHALL update the java.version property in pom.xml to the target Java version
4. THE OpenRewrite_Executor SHALL update the maven.compiler.source and maven.compiler.target properties to match the target Java version
5. WHERE Spring Boot upgrade is required, THE OpenRewrite_Executor SHALL update the Spring Boot parent version in pom.xml
6. THE OpenRewrite_Executor SHALL capture the execution output to a log file named "openrewrite_execution.log"
7. IF OpenRewrite execution fails, THEN THE OpenRewrite_Executor SHALL log the error and halt the workflow
8. THE OpenRewrite_Executor SHALL report the number of files modified by OpenRewrite

### Requirement 4: Post-Upgrade Build Validation

**User Story:** As a developer, I want the system to validate that the project builds successfully after Java upgrade, so that I can be confident the migration was successful.

#### Acceptance Criteria

1. WHEN OpenRewrite execution completes, THE Build_Validator SHALL compile the project using "mvn clean compile"
2. THE Build_Validator SHALL capture the compilation output to a log file named "post_upgrade_build.log"
3. IF the build succeeds, THEN THE Build_Validator SHALL log success and proceed to create a pull request
4. IF the build fails, THEN THE Build_Validator SHALL invoke the Build_Error_Fixer with the build log
5. THE Build_Validator SHALL retry compilation up to 5 times after each Build_Error_Fixer invocation
6. IF the build fails after 5 retry attempts, THEN THE Build_Validator SHALL log failure and halt the workflow
7. THE Build_Validator SHALL report the total number of build attempts and the final build status

### Requirement 5: AI-Powered Post-Upgrade Error Fixing

**User Story:** As a developer, I want the system to automatically fix build errors that occur after Java upgrade, so that manual intervention is minimized.

#### Acceptance Criteria

1. WHEN the Build_Validator detects compilation errors, THE Build_Error_Fixer SHALL parse the build log to extract error messages
2. THE Build_Error_Fixer SHALL group errors by file path
3. FOR ALL files with errors, THE Build_Error_Fixer SHALL invoke AI to generate fixes
4. THE Build_Error_Fixer SHALL provide the AI with the file content and the exact compiler error messages
5. THE Build_Error_Fixer SHALL apply the AI-generated fixes to the source files
6. THE Build_Error_Fixer SHALL preserve the original business logic and only fix compilation errors
7. THE Build_Error_Fixer SHALL generate a report file named "fix_build_errors_report.txt" summarizing the fixes applied

### Requirement 6: Workflow Integration

**User Story:** As a security engineer, I want the Java upgrade capability to be seamlessly integrated into the existing remediation workflow, so that I can use a single workflow for all vulnerability fixes.

#### Acceptance Criteria

1. THE Remediation_Workflow SHALL execute the Java_Upgrade_Analyzer before the Dependency_Fixer
2. THE Remediation_Workflow SHALL branch execution based on the Java_Upgrade_Analyzer recommendation
3. WHERE Java upgrade is not required, THE Remediation_Workflow SHALL execute the existing dependency fix path
4. WHERE Java upgrade is required, THE Remediation_Workflow SHALL execute the OpenRewrite-based upgrade path followed by dependency fixes
5. THE Remediation_Workflow SHALL execute the Build_Error_Fixer self-healing loop after any code changes
6. THE Remediation_Workflow SHALL create a single pull request containing all changes (Java upgrade, dependency updates, and error fixes)
7. THE Remediation_Workflow SHALL include the Java upgrade recommendation in the pull request description

### Requirement 7: Error Handling and Rollback

**User Story:** As a developer, I want the system to handle errors gracefully and provide clear diagnostics, so that I can understand what went wrong and take corrective action.

#### Acceptance Criteria

1. IF the Java_Upgrade_Analyzer fails, THEN THE Remediation_Workflow SHALL log the error and proceed with the current Java version approach
2. IF OpenRewrite execution fails, THEN THE Remediation_Workflow SHALL log the error and halt the workflow without creating a pull request
3. IF the Build_Validator fails after 5 retry attempts, THEN THE Remediation_Workflow SHALL log the error and halt the workflow without creating a pull request
4. THE Remediation_Workflow SHALL preserve all log files (java_upgrade_recommendation.json, openrewrite_execution.log, post_upgrade_build.log, fix_build_errors_report.txt) as workflow artifacts
5. THE Remediation_Workflow SHALL include error messages and log file references in the workflow summary
6. IF any step fails, THEN THE Remediation_Workflow SHALL not push changes to the remote repository
7. THE Remediation_Workflow SHALL provide actionable error messages that guide users to resolve issues

### Requirement 8: OpenRewrite Dependency Management

**User Story:** As a developer, I want the system to ensure OpenRewrite dependencies are available, so that the Java upgrade workflow can execute successfully.

#### Acceptance Criteria

1. THE Recipe_Generator SHALL add the OpenRewrite Maven plugin to pom.xml if it is not already present
2. THE Recipe_Generator SHALL configure the OpenRewrite plugin with the latest stable version
3. THE Recipe_Generator SHALL add the rewrite-migrate-java dependency to the OpenRewrite plugin configuration
4. WHERE Jakarta migration is required, THE Recipe_Generator SHALL add the rewrite-migrate-jakarta dependency
5. THE Recipe_Generator SHALL verify that the OpenRewrite plugin configuration is valid before proceeding
6. IF the OpenRewrite plugin cannot be added, THEN THE Recipe_Generator SHALL log an error and halt the workflow
7. THE Recipe_Generator SHALL preserve any existing OpenRewrite plugin configuration and only add missing elements

### Requirement 9: Spring Boot Compatibility

**User Story:** As a developer, I want the system to ensure Spring Boot compatibility when upgrading Java versions, so that the application continues to function correctly.

#### Acceptance Criteria

1. WHEN upgrading to Java 11, THE Recipe_Generator SHALL verify that the current Spring Boot version (2.7.x) is compatible with Java 11
2. WHEN upgrading to Java 17, THE Recipe_Generator SHALL upgrade Spring Boot to version 3.x
3. THE Recipe_Generator SHALL include the "org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0" recipe when upgrading to Spring Boot 3.x
4. THE Recipe_Generator SHALL update all Spring Boot starter dependencies to the target Spring Boot version
5. THE Recipe_Generator SHALL update Spring Framework dependencies to match the Spring Boot version (5.3.x for Boot 2.x, 6.x for Boot 3.x)
6. IF Spring Boot upgrade is required, THEN THE Recipe_Generator SHALL include javax to jakarta namespace migration recipes
7. THE Recipe_Generator SHALL log the Spring Boot version change in the java_upgrade_recommendation.json file

### Requirement 10: Audit and Reporting

**User Story:** As a security engineer, I want detailed reports of the Java upgrade process, so that I can review what changes were made and why.

#### Acceptance Criteria

1. THE Remediation_Workflow SHALL generate a comprehensive summary report at the end of execution
2. THE summary report SHALL include the Java upgrade recommendation and confidence level
3. THE summary report SHALL include the number of vulnerabilities fixed
4. THE summary report SHALL include the number of files modified by OpenRewrite
5. THE summary report SHALL include the number of build errors fixed by AI
6. THE summary report SHALL include the final build status (success or failure)
7. THE summary report SHALL be included in the GitHub Actions workflow summary
8. THE summary report SHALL be included in the pull request description
9. THE Remediation_Workflow SHALL upload all log files as workflow artifacts for later review
10. THE summary report SHALL include links to all log files and artifacts

