"""
Compatibility Analyzer for Dependency Upgrades

This module analyzes dependency upgrades for breaking changes and generates
code fixes to maintain compatibility. It bridges the gap between dependency
upgrades and code compatibility by identifying files that use upgraded
dependencies and checking for breaking API changes.

Architecture Decision Record (ADR-005): Dependency-Code Compatibility Analysis
- Decision: Analyze code for breaking changes when upgrading dependencies
- Rationale: Dependency upgrades often introduce breaking API changes that cause
  build failures. Without code fixes, automated remediation would break the build.
- Consequences: Requires additional AI analysis step and code modification logic

Design: This component implements a three-phase analysis workflow:
1. Affected File Identification: Find code files that import/use the dependency
2. Breaking Change Detection: Query package registry for changelog and parse for
   breaking changes
3. Code Fix Generation: Use AI to generate fixes for incompatible API usage

For MVP: Basic structure with placeholder logic for AI-based analysis. Breaking
change detection uses simple keyword search in changelogs. Code fix generation
is stubbed out (Phase 4 will integrate with AI).
"""

import os
import re
import json
import logging
import subprocess
from typing import List, Dict, Optional, Set
from pathlib import Path

from normalization.models import DependencyChange, BreakingChange, CodeFix, BuildResult, TestResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CompatibilityAnalyzer:
    """
    Analyzes dependency upgrades for breaking changes and generates code fixes.
    
    This component bridges the gap between dependency upgrades and code
    compatibility. It identifies files that use upgraded dependencies and
    checks for breaking API changes.
    
    Rationale: Dependency upgrades often introduce breaking changes (removed
    methods, changed signatures, renamed classes). Without code fixes, the
    build will fail after dependency upgrades.
    
    Attributes:
        codebase_path: Path to the source code directory
        source_extensions: File extensions to scan for source files
    """
    
    # Source file extensions by package manager
    SOURCE_EXTENSIONS = {
        "maven": [".java"],
        "gradle": [".java", ".kt"],
        "npm": [".js", ".ts", ".jsx", ".tsx"],
        "pip": [".py"],
        "pypi": [".py"],
    }
    
    # Breaking change keywords for changelog parsing
    BREAKING_KEYWORDS = [
        "breaking change",
        "breaking",
        "removed",
        "deprecated",
        "renamed",
        "incompatible",
        "migration",
        "upgrade guide",
    ]
    
    def __init__(self, codebase_path: str = "."):
        """
        Initialize the compatibility analyzer.
        
        Args:
            codebase_path: Path to the source code directory (default: current directory)
        """
        self.codebase_path = Path(codebase_path).resolve()
        logger.info(f"Initialized CompatibilityAnalyzer with codebase path: {self.codebase_path}")
    
    def analyze(
        self,
        dependency_changes: List[DependencyChange],
        source_root: Optional[str] = None
    ) -> List[CodeFix]:
        """
        Analyze dependency changes for code compatibility issues.
        
        This is the main entry point for compatibility analysis. It orchestrates
        the three-phase workflow:
        1. Identify affected code files
        2. Check for breaking changes
        3. Generate code fixes
        
        Args:
            dependency_changes: List of planned dependency upgrades
            source_root: Optional override for source code root directory
        
        Returns:
            List of required code fixes
        
        Algorithm:
        1. For each dependency change, identify affected code files
        2. Check for breaking changes between versions
        3. Generate code fixes for incompatibilities
        
        Example:
            analyzer = CompatibilityAnalyzer()
            changes = [
                DependencyChange(
                    package_name="org.springframework:spring-core",
                    current_version="5.3.0",
                    target_version="6.0.0",
                    package_manager="maven"
                )
            ]
            fixes = analyzer.analyze(changes)
        """
        logger.info(f"Starting compatibility analysis for {len(dependency_changes)} dependency change(s)")
        
        code_fixes = []
        search_root = Path(source_root) if source_root else self.codebase_path
        
        for change in dependency_changes:
            logger.info(
                f"Analyzing {change.package_name}: "
                f"{change.current_version} -> {change.target_version}"
            )
            
            # Phase 1: Identify affected files
            affected_files = self._find_affected_files(change, search_root)
            logger.info(f"  Found {len(affected_files)} affected file(s)")
            
            if not affected_files:
                logger.info(f"  No files import {change.package_name}, skipping")
                continue
            
            # Phase 2: Check for breaking changes
            breaking_changes = self._check_breaking_changes(change)
            logger.info(f"  Detected {len(breaking_changes)} breaking change(s)")
            
            if not breaking_changes:
                logger.info(f"  No breaking changes detected, skipping code fixes")
                continue
            
            # Phase 3: Generate code fixes
            for file_path in affected_files:
                logger.info(f"  Generating fixes for {file_path}")
                fixes = self._generate_fixes(file_path, breaking_changes, change)
                code_fixes.extend(fixes)
        
        logger.info(f"Compatibility analysis complete: {len(code_fixes)} code fix(es) generated")
        return code_fixes
    
    def _find_affected_files(
        self,
        change: DependencyChange,
        search_root: Path
    ) -> List[str]:
        """
        Find code files that import or use the dependency being upgraded.
        
        Strategy:
        - Search for import statements matching the dependency package
        - For Java: search for import statements with groupId.artifactId
        - For Python: search for import statements with package name
        - For JavaScript: search for require() or import statements
        
        Args:
            change: Dependency change to analyze
            search_root: Root directory to search for source files
        
        Returns:
            List of file paths that import the dependency
        
        Implementation Notes:
        - Uses file system walk to find all source files
        - Filters by file extension based on package manager
        - Searches file content for import patterns
        """
        logger.debug(f"Searching for files affected by {change.package_name}")
        
        affected = []
        import_pattern = self._get_import_pattern(change)
        
        if not import_pattern:
            logger.warning(f"Could not determine import pattern for {change.package_name}")
            return affected
        
        # Get source file extensions for this package manager
        extensions = self.SOURCE_EXTENSIONS.get(
            change.package_manager.lower(),
            [".java", ".py", ".js", ".ts"]  # Default fallback
        )
        
        # Walk the source tree
        for root, _, files in os.walk(search_root):
            for file in files:
                if self._is_source_file(file, extensions):
                    file_path = os.path.join(root, file)
                    if self._file_imports_package(file_path, import_pattern):
                        affected.append(file_path)
        
        return affected
    
    def _get_import_pattern(self, change: DependencyChange) -> Optional[re.Pattern]:
        """
        Generate regex pattern to match import statements for the dependency.
        
        Args:
            change: Dependency change to generate pattern for
        
        Returns:
            Compiled regex pattern or None if pattern cannot be determined
        
        Pattern Examples:
        - Java Maven: "org.springframework:spring-core" -> r"import\s+org\.springframework\."
        - Python pip: "requests" -> r"import\s+requests|from\s+requests"
        - JavaScript npm: "lodash" -> r"require\(['\"]lodash|import.*from\s+['\"]lodash"
        """
        package_manager = change.package_manager.lower()
        package_name = change.package_name
        
        if package_manager in ("maven", "gradle"):
            # Java: extract groupId from "groupId:artifactId" format
            if ":" in package_name:
                group_id = package_name.split(":")[0]
                # Convert dots to escaped dots for regex
                escaped_group = group_id.replace(".", r"\.")
                return re.compile(rf"import\s+{escaped_group}\.")
            else:
                # Fallback: treat as simple package name
                escaped_name = package_name.replace(".", r"\.")
                return re.compile(rf"import\s+{escaped_name}\.")
        
        elif package_manager in ("pip", "pypi"):
            # Python: match "import package" or "from package import"
            escaped_name = re.escape(package_name)
            return re.compile(rf"import\s+{escaped_name}|from\s+{escaped_name}")
        
        elif package_manager == "npm":
            # JavaScript: match require('package') or import ... from 'package'
            escaped_name = re.escape(package_name)
            return re.compile(rf"require\(['\"]?{escaped_name}|import.*from\s+['\"]?{escaped_name}")
        
        else:
            logger.warning(f"Unknown package manager: {package_manager}")
            return None
    
    def _is_source_file(self, filename: str, extensions: List[str]) -> bool:
        """
        Check if a file is a source code file based on extension.
        
        Args:
            filename: Name of the file to check
            extensions: List of valid source file extensions
        
        Returns:
            True if the file is a source file, False otherwise
        """
        return any(filename.endswith(ext) for ext in extensions)
    
    def _file_imports_package(self, file_path: str, pattern: re.Pattern) -> bool:
        """
        Check if a file imports the specified package.
        
        Args:
            file_path: Path to the file to check
            pattern: Compiled regex pattern to match import statements
        
        Returns:
            True if the file imports the package, False otherwise
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                return bool(pattern.search(content))
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Could not read file {file_path}: {e}")
            return False
    
    def _check_breaking_changes(self, change: DependencyChange) -> List[BreakingChange]:
        """
        Check for breaking changes between current and target version.
        
        Strategy:
        - Query Maven Central / npm registry for changelog
        - Parse CHANGELOG.md or release notes
        - Look for keywords: "breaking", "removed", "deprecated", "renamed"
        - Use AI to analyze changelog for breaking changes (Phase 4)
        
        Args:
            change: Dependency change to analyze
        
        Returns:
            List of detected breaking changes
        
        Implementation Notes:
        - For MVP: Returns placeholder breaking changes based on keyword search
        - Phase 4 will implement full changelog parsing and AI analysis
        - Queries package registry APIs (Maven Central, npm, PyPI)
        """
        logger.debug(
            f"Checking for breaking changes in {change.package_name} "
            f"({change.current_version} -> {change.target_version})"
        )
        
        # MVP: Placeholder implementation
        # TODO Phase 4: Implement full changelog parsing and AI analysis
        
        breaking_changes = []
        
        # Simulate breaking change detection based on major version bump
        current_major = self._extract_major_version(change.current_version)
        target_major = self._extract_major_version(change.target_version)
        
        if target_major > current_major:
            # Major version bump typically indicates breaking changes
            logger.info(
                f"  Major version bump detected: {current_major} -> {target_major}"
            )
            breaking_changes.append(
                BreakingChange(
                    change_type="major_version_bump",
                    affected_api="unknown",
                    description=(
                        f"Major version upgrade from {change.current_version} to "
                        f"{change.target_version} may contain breaking changes. "
                        f"Review changelog and migration guide."
                    ),
                    migration_guide=self._get_migration_guide_url(change)
                )
            )
        
        # TODO Phase 4: Query package registry for changelog
        # changelog = self._fetch_changelog(change)
        # breaking_changes.extend(self._parse_changelog(changelog))
        
        return breaking_changes
    
    def _extract_major_version(self, version: str) -> int:
        """
        Extract major version number from version string.
        
        Args:
            version: Version string (e.g., "5.3.0", "1.2.3-beta")
        
        Returns:
            Major version number, or 0 if parsing fails
        """
        match = re.match(r"^(\d+)", version)
        if match:
            return int(match.group(1))
        return 0
    
    def _get_migration_guide_url(self, change: DependencyChange) -> Optional[str]:
        """
        Generate URL to migration guide or changelog.
        
        Args:
            change: Dependency change to generate URL for
        
        Returns:
            URL to migration guide or None if not available
        
        Implementation Notes:
        - For Maven: links to Maven Central or GitHub releases
        - For npm: links to npm package page or GitHub releases
        - For pip: links to PyPI or GitHub releases
        """
        package_manager = change.package_manager.lower()
        package_name = change.package_name
        target_version = change.target_version
        
        if package_manager in ("maven", "gradle"):
            # Maven Central search
            if ":" in package_name:
                group_id, artifact_id = package_name.split(":", 1)
                return (
                    f"https://search.maven.org/artifact/"
                    f"{group_id}/{artifact_id}/{target_version}/jar"
                )
        
        elif package_manager == "npm":
            # npm package page
            return f"https://www.npmjs.com/package/{package_name}/v/{target_version}"
        
        elif package_manager in ("pip", "pypi"):
            # PyPI package page
            return f"https://pypi.org/project/{package_name}/{target_version}/"
        
        return None
    
    def _generate_fixes(
        self,
        file_path: str,
        breaking_changes: List[BreakingChange],
        change: DependencyChange
    ) -> List[CodeFix]:
        """
        Generate code fixes for breaking changes in a file.
        
        Strategy:
        - Read source file
        - For each breaking change, identify affected code
        - Generate fix using AI (similar to fix_code_vulnerabilities.py)
        - Return CodeFix objects with file path and fix content
        
        Args:
            file_path: Path to the file to fix
            breaking_changes: List of breaking changes to fix
            change: Dependency change being applied
        
        Returns:
            List of code fixes for the file
        
        Implementation Notes:
        - For MVP: Returns placeholder fixes with descriptive messages
        - Phase 4 will implement AI-based code fix generation
        - Uses similar pattern to fix_code_vulnerabilities.py
        """
        logger.debug(f"Generating fixes for {file_path}")
        
        # MVP: Placeholder implementation
        # TODO Phase 4: Implement AI-based code fix generation
        
        fixes = []
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                original_code = f.read()
            
            for breaking_change in breaking_changes:
                # Placeholder: Generate descriptive fix message
                fix = CodeFix(
                    file_path=file_path,
                    original_code=original_code[:200] + "...",  # Truncate for display
                    fixed_code="[AI-generated fix will be implemented in Phase 4]",
                    reason=(
                        f"Breaking change detected: {breaking_change.description}\n"
                        f"Change type: {breaking_change.change_type}\n"
                        f"Affected API: {breaking_change.affected_api}\n"
                        f"Migration guide: {breaking_change.migration_guide or 'N/A'}\n"
                        f"Dependency: {change.package_name} "
                        f"({change.current_version} -> {change.target_version})"
                    )
                )
                fixes.append(fix)
        
        except (OSError, UnicodeDecodeError) as e:
            logger.error(f"Could not read file {file_path}: {e}")
        
        # TODO Phase 4: Implement AI-based fix generation
        # fixed_code = self._call_ai_fix(original_code, breaking_changes, change)
        # fixes.append(CodeFix(file_path, original_code, fixed_code, reason))
        
        return fixes
    
    def validate_build(
        self,
        package_manager: str = "maven",
        build_dir: Optional[str] = None,
        max_retries: int = 3
    ) -> BuildResult:
        """
        Validate that the project builds successfully.
        
        This method runs the project's build command and captures the output.
        If the build fails, it parses error messages and attempts automated
        error recovery.
        
        Args:
            package_manager: Package manager type (maven, gradle, npm, pip)
            build_dir: Directory to run build in (default: codebase_path)
            max_retries: Maximum number of retry attempts after failures
        
        Returns:
            BuildResult with success status, errors, and output
        
        Implementation Notes:
        - For MVP: Basic build execution with simple error parsing
        - Phase 4 will implement AI-based error recovery
        - Supports common build commands for each package manager
        
        Requirement 16.6: Validate that the build succeeds after applying fixes
        """
        logger.info("Starting build validation")
        
        build_directory = Path(build_dir) if build_dir else self.codebase_path
        build_command = self._get_build_command(package_manager)
        
        if not build_command:
            logger.error(f"Unknown package manager: {package_manager}")
            return BuildResult(
                success=False,
                errors=[f"Unknown package manager: {package_manager}"],
                command="",
                exit_code=-1
            )
        
        # Attempt build with retries
        for attempt in range(max_retries):
            logger.info(f"Build attempt {attempt + 1}/{max_retries}")
            result = self._run_build(build_command, build_directory)
            
            if result.success:
                logger.info("Build succeeded")
                return result
            
            logger.warning(
                f"Build failed (attempt {attempt + 1}/{max_retries})",
                extra={"errors": result.errors}
            )
            
            # Attempt error recovery if not the last attempt
            if attempt < max_retries - 1:
                fixes_applied = self._attempt_error_recovery(result.errors, build_directory)
                if not fixes_applied:
                    logger.error("No automated fixes available for build errors")
                    break
            else:
                logger.error(f"Build failed after {max_retries} attempts")
        
        return result
    
    def _get_build_command(self, package_manager: str) -> Optional[str]:
        """
        Get the build command for a package manager.
        
        Args:
            package_manager: Package manager type
        
        Returns:
            Build command string or None if unknown
        """
        commands = {
            "maven": "mvn compile",
            "gradle": "gradle build -x test",  # Build without running tests
            "npm": "npm run build",
            "pip": "python -m py_compile",  # Basic Python compilation check
            "pypi": "python -m py_compile",
        }
        return commands.get(package_manager.lower())
    
    def _run_build(self, command: str, build_dir: Path) -> BuildResult:
        """
        Execute the build command and capture output.
        
        Args:
            command: Build command to execute
            build_dir: Directory to run build in
        
        Returns:
            BuildResult with execution details
        """
        logger.debug(f"Running build command: {command} in {build_dir}")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(build_dir),
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            output = result.stdout + result.stderr
            success = result.returncode == 0
            
            # Parse errors from output
            errors = self._parse_build_errors(output) if not success else []
            
            return BuildResult(
                success=success,
                errors=errors,
                output=output,
                command=command,
                exit_code=result.returncode
            )
        
        except subprocess.TimeoutExpired:
            logger.error("Build command timed out after 5 minutes")
            return BuildResult(
                success=False,
                errors=["Build timed out after 5 minutes"],
                output="",
                command=command,
                exit_code=-1
            )
        except Exception as e:
            logger.error(f"Build command failed with exception: {e}")
            return BuildResult(
                success=False,
                errors=[f"Build command failed: {str(e)}"],
                output="",
                command=command,
                exit_code=-1
            )
    
    def _parse_build_errors(self, output: str) -> List[str]:
        """
        Parse build output to extract error messages.
        
        Args:
            output: Build output (stdout + stderr)
        
        Returns:
            List of error messages
        
        Implementation Notes:
        - For MVP: Simple pattern matching for common error indicators
        - Phase 4 will implement more sophisticated error parsing
        """
        errors = []
        
        # Common error patterns across build systems
        error_patterns = [
            r"\[ERROR\]\s+(.+)",  # Maven errors
            r"error:\s+(.+)",  # Generic errors
            r"ERROR\s+(.+)",  # Uppercase ERROR
            r"FAILURE:\s+(.+)",  # Gradle failures
            r"Error:\s+(.+)",  # npm errors
            r"SyntaxError:\s+(.+)",  # Python syntax errors
            r"ImportError:\s+(.+)",  # Python import errors
            r"cannot find symbol\s+(.+)",  # Java compilation errors
        ]
        
        for line in output.split("\n"):
            for pattern in error_patterns:
                match = re.search(pattern, line)
                if match:
                    error_msg = match.group(1).strip() if match.lastindex else line.strip()
                    if error_msg and error_msg not in errors:
                        errors.append(error_msg)
        
        # If no specific errors found but build failed, include generic message
        if not errors:
            errors.append("Build failed - see output for details")
        
        return errors
    
    def _attempt_error_recovery(
        self,
        errors: List[str],
        build_dir: Path
    ) -> bool:
        """
        Attempt automated fixes for common build errors.
        
        This method analyzes build errors and applies simple automated fixes
        for common issues like missing imports, deprecated API usage, etc.
        
        Args:
            errors: List of error messages from build
            build_dir: Directory containing the source code
        
        Returns:
            True if fixes were applied, False otherwise
        
        Implementation Notes:
        - For MVP: Simple pattern matching for common errors
        - Phase 4 will implement AI-based error recovery
        - Focuses on import errors and simple API changes
        
        Requirement 16.7: Attempt to fix build errors automatically
        """
        logger.info("Attempting automated error recovery")
        
        fixes_applied = False
        
        for error in errors:
            # Pattern 1: Missing import errors
            if "cannot find symbol" in error.lower() or "cannot resolve" in error.lower():
                logger.info(f"Detected missing import error: {error}")
                # MVP: Log the error, Phase 4 will implement fix
                # TODO Phase 4: Analyze error and add missing imports
                continue
            
            # Pattern 2: Deprecated API usage
            if "deprecated" in error.lower():
                logger.info(f"Detected deprecated API usage: {error}")
                # MVP: Log the error, Phase 4 will implement fix
                # TODO Phase 4: Replace deprecated API calls
                continue
            
            # Pattern 3: Method signature changes
            if "method" in error.lower() and ("not found" in error.lower() or "does not exist" in error.lower()):
                logger.info(f"Detected method signature change: {error}")
                # MVP: Log the error, Phase 4 will implement fix
                # TODO Phase 4: Update method calls to new signature
                continue
        
        if not fixes_applied:
            logger.info("No automated fixes available for current errors")
        
        return fixes_applied
    
    def run_tests(
        self,
        package_manager: str = "maven",
        test_dir: Optional[str] = None
    ) -> TestResult:
        """
        Run the project's test suite and capture results.
        
        This method executes the project's test command and parses the output
        to determine test success/failure status.
        
        Args:
            package_manager: Package manager type (maven, gradle, npm, pip)
            test_dir: Directory to run tests in (default: codebase_path)
        
        Returns:
            TestResult with success status, failures, and output
        
        Implementation Notes:
        - For MVP: Basic test execution with simple output parsing
        - Supports common test commands for each package manager
        - Parses test output to extract failure information
        
        Requirement 16.8: Run the project test suite after applying fixes
        """
        logger.info("Starting test execution")
        
        test_directory = Path(test_dir) if test_dir else self.codebase_path
        test_command = self._get_test_command(package_manager)
        
        if not test_command:
            logger.error(f"Unknown package manager: {package_manager}")
            return TestResult(
                success=False,
                failures=[f"Unknown package manager: {package_manager}"],
                command="",
                exit_code=-1
            )
        
        logger.debug(f"Running test command: {test_command} in {test_directory}")
        
        try:
            result = subprocess.run(
                test_command,
                shell=True,
                cwd=str(test_directory),
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout for tests
            )
            
            output = result.stdout + result.stderr
            success = result.returncode == 0
            
            # Parse test results from output
            failures = self._parse_test_failures(output) if not success else []
            tests_run, tests_failed = self._parse_test_counts(output, package_manager)
            
            logger.info(
                f"Test execution complete: {tests_run} tests run, "
                f"{tests_failed} failed, success={success}"
            )
            
            return TestResult(
                success=success,
                failures=failures,
                output=output,
                command=test_command,
                exit_code=result.returncode,
                tests_run=tests_run,
                tests_failed=tests_failed
            )
        
        except subprocess.TimeoutExpired:
            logger.error("Test command timed out after 10 minutes")
            return TestResult(
                success=False,
                failures=["Tests timed out after 10 minutes"],
                output="",
                command=test_command,
                exit_code=-1
            )
        except Exception as e:
            logger.error(f"Test command failed with exception: {e}")
            return TestResult(
                success=False,
                failures=[f"Test command failed: {str(e)}"],
                output="",
                command=test_command,
                exit_code=-1
            )
    
    def _get_test_command(self, package_manager: str) -> Optional[str]:
        """
        Get the test command for a package manager.
        
        Args:
            package_manager: Package manager type
        
        Returns:
            Test command string or None if unknown
        """
        commands = {
            "maven": "mvn test",
            "gradle": "gradle test",
            "npm": "npm test",
            "pip": "pytest",
            "pypi": "pytest",
        }
        return commands.get(package_manager.lower())
    
    def _parse_test_failures(self, output: str) -> List[str]:
        """
        Parse test output to extract failure messages.
        
        Args:
            output: Test output (stdout + stderr)
        
        Returns:
            List of test failure messages
        """
        failures = []
        
        # Common test failure patterns
        failure_patterns = [
            r"FAILED\s+(.+)",  # Generic FAILED
            r"FAILURE:\s+(.+)",  # Gradle test failures
            r"Tests run:.+Failures:\s+(\d+)",  # Maven test summary
            r"(\d+)\s+failed",  # pytest failures
            r"Error:\s+(.+)",  # npm test errors
            r"AssertionError:\s+(.+)",  # Python assertion errors
        ]
        
        for line in output.split("\n"):
            for pattern in failure_patterns:
                match = re.search(pattern, line)
                if match:
                    failure_msg = match.group(1).strip() if match.lastindex else line.strip()
                    if failure_msg and failure_msg not in failures:
                        failures.append(failure_msg)
        
        # If no specific failures found but tests failed, include generic message
        if not failures:
            failures.append("Tests failed - see output for details")
        
        return failures
    
    def _parse_test_counts(self, output: str, package_manager: str) -> tuple:
        """
        Parse test output to extract test counts.
        
        Args:
            output: Test output (stdout + stderr)
            package_manager: Package manager type (for format-specific parsing)
        
        Returns:
            Tuple of (tests_run, tests_failed)
        """
        tests_run = 0
        tests_failed = 0
        
        # Maven format: "Tests run: 5, Failures: 1, Errors: 0, Skipped: 0"
        maven_match = re.search(r"Tests run:\s+(\d+).*Failures:\s+(\d+)", output)
        if maven_match:
            tests_run = int(maven_match.group(1))
            tests_failed = int(maven_match.group(2))
            return tests_run, tests_failed
        
        # pytest format: "5 passed, 1 failed in 2.34s"
        pytest_match = re.search(r"(\d+)\s+passed.*?(\d+)\s+failed", output)
        if pytest_match:
            passed = int(pytest_match.group(1))
            tests_failed = int(pytest_match.group(2))
            tests_run = passed + tests_failed
            return tests_run, tests_failed
        
        # npm/jest format: "Tests: 1 failed, 5 passed, 6 total"
        npm_match = re.search(r"Tests:\s+(\d+)\s+failed.*?(\d+)\s+passed", output)
        if npm_match:
            tests_failed = int(npm_match.group(1))
            passed = int(npm_match.group(2))
            tests_run = passed + tests_failed
            return tests_run, tests_failed
        
        # Gradle format: "5 tests completed, 1 failed"
        gradle_match = re.search(r"(\d+)\s+tests?\s+completed.*?(\d+)\s+failed", output)
        if gradle_match:
            tests_run = int(gradle_match.group(1))
            tests_failed = int(gradle_match.group(2))
            return tests_run, tests_failed
        
        return tests_run, tests_failed


def main():
    """
    Command-line interface for compatibility analyzer.
    
    Usage:
        python compatibility_analyzer.py
    
    This is a test/demo function for development. In production, the analyzer
    is called by the remediation engine.
    """
    import sys
    
    # Example usage
    analyzer = CompatibilityAnalyzer()
    
    # Test with sample dependency changes
    test_changes = [
        DependencyChange(
            package_name="org.springframework:spring-core",
            current_version="5.3.0",
            target_version="6.0.0",
            package_manager="maven"
        ),
        DependencyChange(
            package_name="lodash",
            current_version="4.17.20",
            target_version="5.0.0",
            package_manager="npm"
        ),
    ]
    
    logger.info("Running compatibility analysis test...")
    fixes = analyzer.analyze(test_changes)
    
    logger.info(f"\nGenerated {len(fixes)} code fix(es):")
    for i, fix in enumerate(fixes, 1):
        logger.info(f"\nFix {i}:")
        logger.info(f"  File: {fix.file_path}")
        logger.info(f"  Reason: {fix.reason}")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
