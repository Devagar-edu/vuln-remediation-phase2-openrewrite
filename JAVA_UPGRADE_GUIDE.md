# Java Upgrade Enhancement - Quick Guide

## Overview

AI-powered Java version upgrade feature integrated into the security remediation workflow. Automatically determines when Java upgrades are needed and performs the migration.

## Quick Start

### Automated (Recommended)

The feature runs automatically in the GitHub Actions workflow:

```bash
# Trigger workflow
gh workflow run Remediation.yml -f scan_json_file="inspector_normalized.json"

# Monitor
gh run watch
```

### Manual Testing

```bash
# 1. Analyze
python .github/scripts/analyze_java_upgrade.py inspector_normalized.json pom.xml src/

# 2. Generate recipe (if upgrade needed)
python .github/scripts/generate_openrewrite_recipe.py java_upgrade_recommendation.json pom.xml src/

# 3. Execute OpenRewrite
mvn org.openrewrite.maven:rewrite-maven-plugin:run

# 4. Update POM
python .github/scripts/update_pom_versions.py java_upgrade_recommendation.json pom.xml

# 5. Build
mvn clean compile
```

## Features

- **AI-Powered Analysis**: Uses GPT-4 to analyze vulnerabilities and determine Java version requirements
- **Intelligent Recipe Selection**: Only includes OpenRewrite recipes that are actually needed
- **Version Alignment**: Ensures all dependencies are compatible with target Java version
- **Automated Migration**: Executes OpenRewrite transformations and updates POM automatically
- **Self-Healing**: AI-powered build error fixing (up to 5 retries)

## Recommendations

| Recommendation | Meaning | Actions |
|----------------|---------|---------|
| `STAY_JAVA_8` | No upgrade needed | Fix dependencies only |
| `UPGRADE_JAVA_11` | Java 11 required | OpenRewrite + POM update |
| `UPGRADE_JAVA_17` | Java 17 required | OpenRewrite + POM + Spring Boot 3 |

## Output Files

- `java_upgrade_recommendation.json` - Analysis results
- `rewrite.yml` - OpenRewrite recipe (if upgrade needed)
- `openrewrite_execution.log` - Execution log (if upgrade needed)
- `build.log` - Build compilation log

## Example Output

```json
{
  "recommendation": "UPGRADE_JAVA_17",
  "confidence": 1.0,
  "current_java_version": "1.8",
  "target_java_version": "17",
  "rationale": "7 vulnerabilities require Java version upgrade",
  "vulnerabilities_requiring_upgrade": [...],
  "all_vulnerabilities_addressed": [...],
  "spring_boot_upgrade_required": true,
  "target_spring_boot_version": "3.0.0",
  "migration_complexity": "LOW"
}
```

## Workflow Integration

The feature is integrated into `.github/workflows/Remediation.yml`:

```
1. Load Scan JSON
2. AI Java Upgrade Analysis ⭐
3. Generate OpenRewrite Recipe ⭐ (if upgrade needed)
4. Execute OpenRewrite ⭐ (if upgrade needed)
5. Update POM Versions ⭐ (if upgrade needed)
6. Fix Dependencies (only if STAY_JAVA_8) ⭐
7. Self-Healing Build Loop
8. Create PR with upgrade details ⭐
```

**Important**: When Java upgrade is performed, dependency versions are already aligned by the analyzer. The `Fix Dependencies` step only runs when staying on Java 8.

## Configuration

### Optional: Set GitHub Token for AI Features

```bash
export GITHUB_TOKEN="your_token_here"
```

If not set, the feature falls back to intelligent heuristics.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| AI analysis fails | Falls back to heuristics automatically |
| OpenRewrite fails | Check `openrewrite_execution.log` |
| Build fails | Self-healing loop runs automatically (5 retries) |

## Monitoring

```bash
# List recent runs
gh run list --workflow=Remediation.yml --limit 5

# View run details
gh run view <run-id>

# Download artifacts
gh run download <run-id>

# View PR
gh pr view <pr-number>
```

## Sample Data

- `inspector_normalized.json` - Normalized format (requires Java 17)
- `aws-inspector-findings.json` - Raw format (stays on Java 8)

## Requirements

- Python 3.9+
- Maven 3.6+
- GitHub Token (optional, for AI features)

## Support

For detailed technical specifications, see:
- `.kiro/specs/java-upgrade-enhancement/requirements.md`
- `.kiro/specs/java-upgrade-enhancement/design.md`

---

**Version**: 1.0.0  
**Status**: Production Ready ✅
