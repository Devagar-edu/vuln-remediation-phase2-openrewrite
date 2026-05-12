# AI-Powered Dependency Upgrade System

## Overview

The `fix_dependencies.py` script now uses AI to make intelligent decisions about dependency version upgrades, rather than blindly trusting scanner reports. This prevents build failures from non-existent versions.

## Problem Solved

**Before**: Scanner reports (Snyk, AWS Inspector) sometimes suggest versions that don't exist in Maven Central, causing build failures.

**After**: AI validates versions against Maven Central and suggests safe alternatives when needed.

## How It Works

### 3-Step Validation Process

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Verify Scanner Suggestion                          │
│ ─────────────────────────────────────────────────────────── │
│ Check if scanner's suggested version exists in Maven Central│
│                                                             │
│ ✓ Exists → Use it                                          │
│ ✗ Not found → Go to Step 2                                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Fetch Available Versions                           │
│ ─────────────────────────────────────────────────────────── │
│ Query Maven Central API for latest 20 versions             │
│                                                             │
│ ✓ Found versions → Go to Step 3                            │
│ ✗ No versions → Skip this dependency                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 3: AI Decision                                         │
│ ─────────────────────────────────────────────────────────── │
│ AI analyzes:                                                │
│ • Current version                                           │
│ • Scanner suggestion                                        │
│ • Available versions in Maven Central                      │
│ • POM context (Spring Boot version, etc.)                  │
│                                                             │
│ AI selects:                                                 │
│ • Newest stable version that fixes the vulnerability       │
│ • Avoids alpha, beta, RC, SNAPSHOT releases                │
│ • Considers framework compatibility                        │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### 1. Maven Central Verification
- Checks if versions actually exist before attempting upgrade
- Uses Maven Central REST API for real-time validation
- Prevents "artifact not found" build failures

### 2. AI-Powered Version Selection
- Analyzes available versions intelligently
- Prefers stable releases over pre-release versions
- Considers Spring Boot and framework compatibility
- Finds closest safe alternative when scanner suggestion is invalid

### 3. Smart Filtering
- Excludes unstable versions: alpha, beta, RC, SNAPSHOT, M1, M2
- Prioritizes security fixes while maintaining stability
- Respects semantic versioning principles

### 4. Detailed Logging
- Shows verification status for each dependency
- Logs AI corrections when scanner suggestions are invalid
- Provides clear summary of all actions taken

## Example Output

```
======================================================================
Processing: org.springframework:spring-core
  Current version: 5.3.20
  Scanner suggested: 5.3.99
  ✗ Scanner version NOT found in Maven Central
  → Fetching available versions from Maven Central...
  → Found 20 versions in Maven Central
  → AI analyzing safe upgrade path for org.springframework:spring-core...
  ✓ AI recommends version: 5.3.30
  ✓ AI corrected version: 5.3.99 → 5.3.30
  → Applying version update to 5.3.30...
  ✓ Dependency updated successfully
======================================================================

======================================================================
Dependency Update Summary
======================================================================
Total findings processed:        15
Successfully updated:            12
AI-corrected versions:           3
Skipped (no fix available):      2
Not found in pom.xml:            1
======================================================================
✅ Dependency updates completed!
   AI corrected 3 invalid scanner suggestions
```

## AI Decision Logic

The AI uses the following criteria to select versions:

### Priority 1: Stability
- Excludes: alpha, beta, RC, SNAPSHOT, M1, M2
- Prefers: GA (General Availability) releases

### Priority 2: Security
- Selects versions that fix the reported vulnerability
- Considers CVE information when available

### Priority 3: Compatibility
- Analyzes POM context for framework versions
- Ensures Spring Boot compatibility
- Respects major version boundaries when appropriate

### Priority 4: Recency
- Among stable versions, prefers newer releases
- Balances security fixes with stability

## Configuration

### Required Environment Variables
```bash
GITHUB_TOKEN=<your-github-token>  # Required for AI API access
```

### Maven Central API
- No authentication required
- Rate limit: ~1000 requests/hour
- Automatic retry with exponential backoff

## Error Handling

### Network Failures
- Automatic retry with exponential backoff (3 attempts)
- Graceful degradation if Maven Central is unavailable
- Clear error messages for debugging

### Invalid Versions
- Skips dependencies when no safe version found
- Logs reason for skipping
- Continues processing remaining dependencies

### Maven Command Failures
- Captures and logs Maven error output
- Doesn't fail entire process on single dependency failure
- Provides actionable error messages

## Usage

### Standard Usage (from workflow)
```bash
python .github/scripts/fix_dependencies.py <scan_report.json> pom.xml
```

### Manual Testing
```bash
# Set required environment variable
export GITHUB_TOKEN=<your-token>

# Run the script
python .github/scripts/fix_dependencies.py inspector_normalized.json pom.xml

# Verify changes
mvn clean compile
```

## Integration with Workflows

The script is automatically called by:
- `.github/workflows/Remediation.yml` - AI Security Remediation workflow
- Processes both Snyk and AWS Inspector findings
- Works with normalized schema format

## Benefits

### 1. Prevents Build Failures
- No more "artifact not found" errors from invalid versions
- Validates before applying changes

### 2. Intelligent Upgrades
- AI considers context and compatibility
- Finds best available version, not just any version

### 3. Maintains Stability
- Avoids pre-release versions
- Respects framework compatibility

### 4. Transparency
- Detailed logging of all decisions
- Clear indication when AI corrects scanner suggestions
- Summary statistics for audit trail

## Limitations

### Maven Central Only
- Currently only checks Maven Central repository
- Private/enterprise repositories not supported
- Can be extended to support additional repositories

### AI Model Dependency
- Requires GitHub Models API access
- Falls back to newest stable version if AI fails
- Rate limits apply (handled with retry logic)

### Version Selection
- AI makes best-effort decisions
- Manual review recommended for critical dependencies
- Test thoroughly after upgrades

## Troubleshooting

### "Rate limited (429)" errors
- Script automatically retries with exponential backoff
- If persistent, wait a few minutes and retry
- Check GitHub Models API quota

### "Could not fetch versions from Maven Central"
- Check network connectivity
- Verify Maven Central is accessible
- May be temporary API issue - retry later

### "No safe upgrade version found"
- Dependency may not have newer stable versions
- Check Maven Central manually for available versions
- May need to wait for upstream fix

### Maven command failures
- Check Maven is installed and in PATH
- Verify pom.xml is valid
- Review Maven error output in logs

## Future Enhancements

### Planned Features
1. Support for private Maven repositories
2. Batch processing optimization
3. Caching of Maven Central queries
4. Integration with dependency-check for CVE validation
5. Support for Gradle projects

### Extensibility
The script is designed to be extended:
- Add custom version selection logic
- Integrate additional vulnerability databases
- Support custom repository configurations
- Add project-specific compatibility rules

## Related Documentation

- [Schema Compatibility Verification](.github/scripts/SCHEMA_COMPATIBILITY_VERIFICATION.md)
- [Implementation Guide](.github/scripts/IMPLEMENTATION_GUIDE.md)
- [Project Structure Validation](.github/scripts/PROJECT_STRUCTURE_VALIDATION.md)
