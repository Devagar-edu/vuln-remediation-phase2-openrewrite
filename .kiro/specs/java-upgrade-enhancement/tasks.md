# Implementation Plan: Java Upgrade Enhancement

## Overview

This implementation plan breaks down the Java Upgrade Enhancement feature into discrete, actionable coding tasks. The feature adds intelligent Java version upgrade capabilities to the existing AI-powered security remediation workflow. Implementation follows a sequential approach: analyzer → recipe generator → POM updater → build error fixer → workflow integration → testing.

## Tasks

- [ ] 1. Implement Java Upgrade Analyzer
  - [x] 1.1 Create analyze_java_upgrade.py script with core analysis logic
    - Create `.github/scripts/analyze_java_upgrade.py`
    - Implement `extract_java_version(pom)` function to parse current Java version from pom.xml
    - Implement `extract_spring_boot_version(pom)` function to parse Spring Boot version
    - Implement `get_fix_requirements(vuln)` function to determine minimum Java version for vulnerability fix
    - Implement `check_spring_boot_compatibility(spring_boot_version, target_java)` function
    - Implement `assess_migration_complexity(src_dir, current_java, target_java)` function
    - Implement `calculate_confidence(vulns, complexity)` function
    - Implement `generate_rationale(vulns)` function
    - Implement main `analyze_java_upgrade(findings, pom, src_dir)` function with decision logic
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [ ]* 1.2 Write property test for recommendation validity
    - **Property 1: Recommendation Validity**
    - **Validates: Requirements 1.3**
    - Create test file `tests/test_analyze_java_upgrade_properties.py`
    - Implement vulnerability findings generator
    - Implement POM configuration generator
    - Write property test verifying recommendation is one of three valid values
    - Configure minimum 100 iterations

  - [x] 1.3 Add JSON output generation for recommendation
    - Implement function to write `java_upgrade_recommendation.json` with all required fields
    - Include recommendation, confidence, current/target versions, rationale, vulnerabilities list
    - Include Spring Boot upgrade info and migration complexity
    - _Requirements: 1.6, 1.7_

  - [ ]* 1.4 Write unit tests for specific analyzer scenarios
    - Test STAY_JAVA_8 recommendation when all vulnerabilities fixable in Java 8
    - Test UPGRADE_JAVA_11 recommendation for Java 11-requiring vulnerabilities
    - Test UPGRADE_JAVA_17 recommendation for Java 17-requiring vulnerabilities
    - Test Spring Boot compatibility detection
    - _Requirements: 1.3, 1.4, 1.5_

- [x] 2. Checkpoint - Verify analyzer implementation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Implement Recipe Generator
  - [x] 3.1 Create generate_openrewrite_recipe.py script
    - Create `.github/scripts/generate_openrewrite_recipe.py`
    - Define JAVA_11_RECIPE_TEMPLATE constant with OpenRewrite recipe structure
    - Define JAVA_17_RECIPE_TEMPLATE constant
    - Define SPRING_BOOT_3_RECIPES constant
    - Implement `write_yaml(filename, recipe)` function
    - Implement `add_openrewrite_plugin(pom_file, recipe_name, dependencies)` function to update pom.xml
    - Implement main `generate_recipe(recommendation, pom_file)` function with recipe selection logic
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [ ]* 3.2 Write property test for recipe selection correctness
    - **Property 5: Recipe Selection Correctness**
    - **Validates: Requirements 2.2, 2.3, 2.4, 2.5**
    - Create test file `tests/test_recipe_generator_properties.py`
    - Implement recipe configuration generator
    - Write property test verifying correct recipes included for target version
    - Verify Spring Boot 3 recipes included when required

  - [ ]* 3.3 Write property test for recipe file validity
    - **Property 6: Recipe File Validity**
    - **Validates: Requirements 2.7**
    - Write property test that generates recipes and validates YAML syntax
    - Use PyYAML to parse generated recipe files
    - Verify no parsing errors occur

  - [ ]* 3.4 Write unit tests for recipe generation
    - Test Java 11 recipe includes "Java8toJava11"
    - Test Java 17 recipe includes "UpgradeToJava17" and "JavaxMigrationToJakarta"
    - Test Spring Boot 3 recipe includes "UpgradeSpringBoot_3_0"
    - Test POM plugin configuration added correctly
    - _Requirements: 2.2, 2.3, 2.4, 2.5_

- [ ] 4. Implement POM Updater
  - [x] 4.1 Create update_pom_versions.py script
    - Create `.github/scripts/update_pom_versions.py`
    - Implement `parse_xml(pom_file)` function using lxml
    - Implement `update_property(tree, property_name, value)` function
    - Implement `update_parent_version(tree, artifact_id, version)` function
    - Implement `get_compatible_spring_version(spring_boot_version)` function
    - Implement `update_dependency_versions(tree, group_id, version)` function
    - Implement `write_xml(pom_file, tree)` function
    - Implement main `update_pom(pom_file, target_java, target_spring_boot)` function
    - _Requirements: 3.3, 3.4, 3.5_

  - [ ]* 4.2 Write property test for POM consistency after upgrade
    - **Property 7: POM Consistency After Upgrade**
    - **Validates: Requirements 3.3, 3.4, 3.5**
    - Create test file `tests/test_pom_updater_properties.py`
    - Implement POM configuration generator
    - Write property test verifying java.version, maven.compiler.source, and maven.compiler.target all match
    - Verify Spring Boot and Spring Framework versions compatible when upgraded

  - [ ]* 4.3 Write unit tests for POM transformations
    - Test java.version updated from 1.8 to 11
    - Test java.version updated from 1.8 to 17
    - Test Spring Boot parent updated from 2.7.18 to 3.0.0
    - Test Spring Framework dependencies updated from 5.3.x to 6.0.x
    - Test all three Java properties updated consistently
    - _Requirements: 3.3, 3.4, 3.5_

- [ ] 5. Implement Build Error Fixer
  - [x] 5.1 Create fix_build_errors.py script
    - Create `.github/scripts/fix_build_errors.py`
    - Implement `parse_compilation_errors(build_log)` function to extract error messages
    - Implement `group_by_file(errors)` function to organize errors by file path
    - Implement `format_errors(file_errors)` function for AI prompt
    - Implement `call_github_models_api(prompt)` function for AI fix generation
    - Implement `generate_report(filename, fixes_applied)` function
    - Implement main `fix_build_errors(build_log, pom_file, src_dir)` function
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

  - [ ]* 5.2 Write property test for build error extraction and grouping
    - **Property 8: Build Error Extraction and Grouping**
    - **Validates: Requirements 5.1, 5.2**
    - Create test file `tests/test_build_error_fixer_properties.py`
    - Implement build log generator with random compilation errors
    - Write property test verifying all errors extracted
    - Verify each file appears exactly once in grouping with all its errors

  - [ ]* 5.3 Write property test for AI fix invocation completeness
    - **Property 9: AI Fix Invocation Completeness**
    - **Validates: Requirements 5.3, 5.4**
    - Write property test verifying AI invoked exactly once per file with errors
    - Verify file content and error messages provided to AI

  - [ ]* 5.4 Write unit tests for specific error patterns
    - Test javax.persistence import error fixed to jakarta.persistence
    - Test deprecated API usage fixed
    - Test type inference error fixed
    - Test error parsing from Maven build log format
    - _Requirements: 5.1, 5.2, 5.5, 5.6_

- [x] 6. Checkpoint - Verify core components implementation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Integrate components into Remediation workflow
  - [ ] 7.1 Add Java Upgrade Analyzer step to Remediation.yml
    - Add "Analyze Java Version Upgrade Recommendation" step after "Load Scan JSON" steps
    - Configure step to run `python .github/scripts/analyze_java_upgrade.py snyk.json pom.xml src/`
    - Add logic to check if `java_upgrade_recommendation.json` exists
    - Extract recommendation value and set `JAVA_UPGRADE_RECOMMENDATION` environment variable
    - Add fallback to "STAY_JAVA_8" if analysis fails
    - _Requirements: 6.1, 6.2, 7.1_

  - [ ] 7.2 Add conditional OpenRewrite recipe generation step
    - Add "Generate OpenRewrite Recipe" step with condition `if: env.JAVA_UPGRADE_RECOMMENDATION != 'STAY_JAVA_8'`
    - Configure step to run `python .github/scripts/generate_openrewrite_recipe.py java_upgrade_recommendation.json pom.xml`
    - _Requirements: 6.4, 2.1_

  - [ ] 7.3 Add OpenRewrite execution step
    - Add "Execute OpenRewrite Migration" step with condition `if: env.JAVA_UPGRADE_RECOMMENDATION != 'STAY_JAVA_8'`
    - Configure step to run `mvn org.openrewrite.maven:rewrite-maven-plugin:run`
    - Capture output to `openrewrite_execution.log`
    - Add success/failure detection logic
    - Add error handling to halt workflow on failure
    - _Requirements: 3.1, 3.2, 3.7, 7.2_

  - [ ] 7.4 Add POM version update step
    - Add "Update POM Versions" step with condition `if: env.JAVA_UPGRADE_RECOMMENDATION != 'STAY_JAVA_8'`
    - Configure step to run `python .github/scripts/update_pom_versions.py java_upgrade_recommendation.json pom.xml`
    - _Requirements: 3.3, 3.4, 3.5, 6.4_

  - [ ] 7.5 Update self-healing build loop to use fix_build_errors.py
    - Modify existing "Self-Healing Build (AI Loop)" step
    - Replace `python .github/scripts/fix_imports.py` with `python .github/scripts/fix_build_errors.py`
    - Update to capture output to `post_upgrade_build.log` or `build.log`
    - Ensure MAX_RETRIES=5 is enforced
    - _Requirements: 4.1, 4.2, 4.4, 4.5, 4.6, 4.7, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

  - [ ] 7.6 Add artifact upload step for all log files
    - Add "Upload Logs and Reports" step with `if: always()` condition
    - Configure to upload `java_upgrade_recommendation.json`, `openrewrite_execution.log`, `post_upgrade_build.log`, `fix_build_errors_report.txt`, `build.log`
    - Use `actions/upload-artifact@v4`
    - _Requirements: 7.4, 10.9_

  - [ ] 7.7 Update PR creation to include Java upgrade information
    - Modify "Create PR" step to read `java_upgrade_recommendation.json`
    - Include recommendation and rationale in PR description
    - Include links to uploaded artifacts
    - _Requirements: 6.6, 6.7_

  - [ ]* 7.8 Write integration test for workflow branching consistency
    - **Property 4: Workflow Branching Consistency**
    - **Validates: Requirements 1.4, 1.5, 6.2, 6.3, 6.4**
    - Create test file `tests/test_workflow_integration.py`
    - Write test verifying STAY_JAVA_8 skips OpenRewrite steps
    - Write test verifying UPGRADE_JAVA_11 executes OpenRewrite steps
    - Write test verifying UPGRADE_JAVA_17 executes OpenRewrite steps

- [ ] 8. Implement workflow summary report generation
  - [ ] 8.1 Create generate_summary_report.py script
    - Create `.github/scripts/generate_summary_report.py`
    - Implement function to read all log files and extract metrics
    - Implement function to format summary report in Markdown
    - Include Java upgrade recommendation, confidence, vulnerabilities fixed, files modified, build errors fixed, final build status
    - Include links to all log files and artifacts
    - Write output to `$GITHUB_STEP_SUMMARY`
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.10_

  - [ ] 8.2 Add summary report generation step to workflow
    - Add "Generate Workflow Summary" step at end of workflow with `if: always()` condition
    - Configure to run `python .github/scripts/generate_summary_report.py`
    - _Requirements: 10.1, 10.7_

  - [ ]* 8.3 Write property test for summary report completeness
    - **Property 14: Summary Report Completeness**
    - **Validates: Requirements 10.2, 10.3, 10.4, 10.5, 10.6, 10.10**
    - Create test file `tests/test_summary_report_properties.py`
    - Implement workflow execution result generator
    - Write property test verifying all required fields present in summary
    - Verify links to log files included

- [ ] 9. Checkpoint - Verify workflow integration
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Add error handling and rollback mechanisms
  - [ ] 10.1 Add error handling to analyze_java_upgrade.py
    - Wrap main logic in try-except block
    - Log errors with full stack trace
    - Return safe fallback recommendation on failure
    - _Requirements: 7.1_

  - [ ] 10.2 Add error handling to generate_openrewrite_recipe.py
    - Wrap main logic in try-except block
    - Validate recipe file syntax before proceeding
    - Exit with error code on failure
    - _Requirements: 7.2, 8.5, 8.6_

  - [ ] 10.3 Add error handling to update_pom_versions.py
    - Wrap XML parsing in try-except block
    - Validate XML structure before writing
    - Exit with error code on failure
    - _Requirements: 7.2_

  - [ ] 10.4 Add error handling to fix_build_errors.py
    - Wrap main logic in try-except block
    - Handle AI API failures gracefully
    - Log errors and continue to next file
    - _Requirements: 7.3_

  - [ ] 10.5 Add workflow-level error handling
    - Ensure failed steps halt workflow and prevent PR creation
    - Verify changes not pushed to remote on failure
    - Add diagnostic error messages following template format
    - _Requirements: 7.2, 7.3, 7.5, 7.6, 7.7_

  - [ ]* 10.6 Write integration test for failure prevents push
    - **Property 16: Failure Prevents Push**
    - **Validates: Requirements 7.6**
    - Write test simulating workflow failure
    - Verify no changes pushed to remote repository

- [ ] 11. Add property-based tests for remaining properties
  - [ ]* 11.1 Write property test for recommendation file creation
    - **Property 2: Recommendation File Creation**
    - **Validates: Requirements 1.7**
    - Write property test verifying file created for any analyzer execution

  - [ ]* 11.2 Write property test for recommendation completeness
    - **Property 3: Recommendation Completeness**
    - **Validates: Requirements 1.6**
    - Write property test verifying all required fields present in recommendation

  - [ ]* 11.3 Write property test for output file naming consistency
    - **Property 10: Output File Naming Consistency**
    - **Validates: Requirements 1.7, 2.6, 3.6, 4.2, 5.7**
    - Write property test verifying all components create files with specified names

  - [ ]* 11.4 Write property test for OpenRewrite plugin configuration preservation
    - **Property 11: OpenRewrite Plugin Configuration Preservation**
    - **Validates: Requirements 8.7**
    - Implement POM generator with existing OpenRewrite configuration
    - Write property test verifying existing config preserved

  - [ ]* 11.5 Write property test for plugin dependency completeness
    - **Property 12: Plugin Dependency Completeness**
    - **Validates: Requirements 8.3, 8.4**
    - Write property test verifying rewrite-migrate-java always included
    - Verify rewrite-migrate-jakarta included when Jakarta migration required

  - [ ]* 11.6 Write property test for Spring Boot compatibility enforcement
    - **Property 13: Spring Boot Compatibility Enforcement**
    - **Validates: Requirements 9.1, 9.2, 9.5**
    - Write property test verifying Java 17 upgrades include Spring Boot 3.x
    - Verify Java 11 upgrades maintain Spring Boot 2.7.x compatibility

  - [ ]* 11.7 Write property test for artifact preservation
    - **Property 15: Artifact Preservation**
    - **Validates: Requirements 7.4, 10.9**
    - Write property test verifying all log files uploaded as artifacts

  - [ ]* 11.8 Write property test for build retry limit
    - **Property 17: Build Retry Limit**
    - **Validates: Requirements 4.5, 4.6**
    - Write property test verifying exactly 5 retries occur before halt

- [ ] 12. Add end-to-end integration tests
  - [ ]* 12.1 Write integration test for Java 11 upgrade flow
    - Create test Java 8 project with vulnerabilities requiring Java 11
    - Run full workflow
    - Verify Java 11 upgrade applied
    - Verify project compiles successfully
    - Verify PR created with correct information

  - [ ]* 12.2 Write integration test for Java 17 upgrade with Spring Boot 3
    - Create test Java 8 Spring Boot 2.7 project
    - Run full workflow
    - Verify Java 17 and Spring Boot 3 upgrade applied
    - Verify javax → jakarta migration applied
    - Verify project compiles successfully
    - Verify PR created

  - [ ]* 12.3 Write integration test for dependency-only fix path
    - Create test project with vulnerabilities fixable in Java 8
    - Run workflow
    - Verify no Java upgrade performed
    - Verify dependencies updated
    - Verify project compiles

  - [ ]* 12.4 Write integration test for build error self-healing
    - Create test project with post-migration compilation errors
    - Run workflow
    - Verify Build_Error_Fixer invoked
    - Verify errors fixed within 5 retries
    - Verify project compiles

  - [ ]* 12.5 Write integration test for OpenRewrite failure handling
    - Simulate OpenRewrite execution failure
    - Run workflow
    - Verify workflow halts
    - Verify no PR created
    - Verify logs uploaded as artifacts

- [ ] 13. Final checkpoint - Complete testing and validation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Update documentation
  - [ ] 14.1 Update README.md with Java upgrade feature description
    - Add section describing Java upgrade enhancement
    - Document when Java upgrades are triggered
    - Document supported upgrade paths (Java 8→11, Java 8→17)
    - Include example workflow execution

  - [ ] 14.2 Create user guide for Java upgrade feature
    - Create `.github/docs/java-upgrade-guide.md`
    - Document how to interpret upgrade recommendations
    - Document how to troubleshoot upgrade failures
    - Include common error patterns and solutions
    - Document rollback procedures

  - [ ] 14.3 Add inline code documentation
    - Add docstrings to all Python functions
    - Add comments explaining complex logic
    - Add type hints to function signatures
    - Document expected input/output formats

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Property tests validate universal correctness properties with 100+ iterations
- Unit tests validate specific examples and edge cases
- Integration tests validate end-to-end workflows
- All scripts use Python 3.9+ for consistency with existing codebase
- OpenRewrite plugin version 5.42.0+ required
- GitHub Models API used for AI-powered analysis and fixes
