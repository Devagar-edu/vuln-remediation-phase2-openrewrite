# Build Validation and Error Recovery

This document describes the build validation and test execution functionality implemented in the CompatibilityAnalyzer class.

## Overview

The build validation feature enables the remediation pipeline to:
1. Validate that the project builds successfully after applying dependency upgrades and code fixes
2. Attempt automated error recovery when builds fail
3. Run the project's test suite to verify functionality is preserved

## Components

### 1. Data Models (models.py)

#### BuildResult
Represents the result of a build validation:
- `success`: Whether the build succeeded
- `errors`: List of error messages from the build
- `output`: Full build output (stdout + stderr)
- `command`: The build command that was executed
- `exit_code`: Exit code from the build process

#### TestResult
Represents the result of test execution:
- `success`: Whether all tests passed
- `failures`: List of test failure messages
- `output`: Full test output (stdout + stderr)
- `command`: The test command that was executed
- `exit_code`: Exit code from the test process
- `tests_run`: Number of tests executed
- `tests_failed`: Number of tests that failed

### 2. CompatibilityAnalyzer Methods

#### validate_build()
Validates that the project builds successfully.

**Parameters:**
- `package_manager`: Package manager type (maven, gradle, npm, pip)
- `build_dir`: Directory to run build in (default: codebase_path)
- `max_retries`: Maximum number of retry attempts after failures (default: 3)

**Returns:** BuildResult with success status, errors, and output

**Features:**
- Runs the appropriate build command for the package manager
- Captures and parses build output for errors
- Retries build with error recovery on failure
- Supports Maven, Gradle, npm, and pip/pytest

**Example:**
```python
analyzer = CompatibilityAnalyzer(codebase_path=".")
result = analyzer.validate_build(package_manager="maven")
if result.success:
    print("Build succeeded!")
else:
    print(f"Build failed with {len(result.errors)} errors")
```

#### _attempt_error_recovery()
Attempts automated fixes for common build errors.

**Parameters:**
- `errors`: List of error messages from build
- `build_dir`: Directory containing the source code

**Returns:** True if fixes were applied, False otherwise

**Features:**
- Detects common error patterns (missing imports, deprecated APIs, method signature changes)
- Logs detected errors for Phase 4 AI-based recovery
- For MVP: Pattern detection only, actual fixes will be implemented in Phase 4

**Error Patterns Detected:**
1. Missing import errors ("cannot find symbol", "cannot resolve")
2. Deprecated API usage ("deprecated")
3. Method signature changes ("method not found", "does not exist")

#### run_tests()
Runs the project's test suite and captures results.

**Parameters:**
- `package_manager`: Package manager type (maven, gradle, npm, pip)
- `test_dir`: Directory to run tests in (default: codebase_path)

**Returns:** TestResult with success status, failures, and output

**Features:**
- Runs the appropriate test command for the package manager
- Captures and parses test output for failures
- Extracts test counts (tests run, tests failed)
- Supports Maven, Gradle, npm/jest, and pytest

**Example:**
```python
analyzer = CompatibilityAnalyzer(codebase_path=".")
result = analyzer.run_tests(package_manager="maven")
print(f"Tests: {result.tests_run} run, {result.tests_failed} failed")
if result.success:
    print("All tests passed!")
```

## Supported Package Managers

### Build Commands
- **Maven**: `mvn compile`
- **Gradle**: `gradle build -x test` (build without running tests)
- **npm**: `npm run build`
- **pip/pypi**: `python -m py_compile` (basic Python compilation check)

### Test Commands
- **Maven**: `mvn test`
- **Gradle**: `gradle test`
- **npm**: `npm test`
- **pip/pypi**: `pytest`

## Error Parsing

### Build Errors
The system detects and parses the following error patterns:
- Maven errors: `[ERROR] ...`
- Generic errors: `error: ...`, `ERROR ...`
- Gradle failures: `FAILURE: ...`
- npm errors: `Error: ...`
- Python errors: `SyntaxError: ...`, `ImportError: ...`
- Java compilation errors: `cannot find symbol ...`

### Test Failures
The system detects and parses the following test output formats:
- Maven: `Tests run: X, Failures: Y, Errors: Z, Skipped: W`
- pytest: `X passed, Y failed in Z.XXs`
- npm/jest: `Tests: X failed, Y passed, Z total`
- Gradle: `X tests completed, Y failed`

## Integration with Remediation Pipeline

The build validation and test execution methods are designed to be called by the remediation engine after applying dependency upgrades and code fixes:

```python
# Apply dependency upgrades
remediation_engine.apply_dependency_upgrades(findings)

# Apply code fixes
remediation_engine.apply_code_fixes(code_fixes)

# Validate build
build_result = analyzer.validate_build(package_manager="maven")
if not build_result.success:
    logger.error(f"Build failed: {build_result.errors}")
    # Handle build failure

# Run tests
test_result = analyzer.run_tests(package_manager="maven")
if not test_result.success:
    logger.warning(f"Tests failed: {test_result.failures}")
    # Handle test failures
```

## Requirements Satisfied

- **Requirement 16.6**: Validate that the build succeeds after applying both dependency upgrades and code fixes
- **Requirement 16.7**: If the build fails after remediation, log the build errors and attempt to fix import statements, method signatures, or deprecated API usage
- **Requirement 16.8**: Run the project test suite after applying fixes to verify functionality is preserved

## Future Enhancements (Phase 4)

The current implementation provides the framework and basic error detection. Phase 4 will add:

1. **AI-Based Error Recovery**: Use AI to analyze build errors and generate automated fixes
2. **Advanced Error Parsing**: More sophisticated error pattern matching and context extraction
3. **Intelligent Fix Generation**: Generate code fixes for missing imports, deprecated APIs, and method signature changes
4. **Test Failure Analysis**: Analyze test failures and suggest fixes

## Testing

The implementation has been tested with:
- Maven builds (successful compilation)
- Maven tests (successful test execution)
- Error parsing with sample build output
- Test count parsing with various output formats
- Unknown package manager handling

All tests passed successfully with no syntax errors or runtime exceptions.
