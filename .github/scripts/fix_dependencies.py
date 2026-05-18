import json
import subprocess
import sys
import requests
import time
import re
from defusedxml.ElementTree import parse   
import os


BASE_DIR = os.getcwd()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # Optional - only needed for AI features

MAX_RETRIES = 3

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)


def call_with_retry(fn, *args, **kwargs):
    """Call function with exponential backoff retry on rate limit."""
    for attempt in range(MAX_RETRIES):
        try:
            return fn(*args, **kwargs)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                wait = (2 ** attempt) + 1
                print(f"  ⚠ Rate limited (429). Retrying in {wait}s... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(wait)
            else:
                raise
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            wait = (2 ** attempt) + 1
            print(f"  ⚠ Network error: {e}. Retrying in {wait}s...")
            time.sleep(wait)
    raise RuntimeError(f"API call failed after {MAX_RETRIES} retries.")


def check_maven_central(group_id, artifact_id, version):
    """
    Check if a specific version exists in Maven Central.
    
    Returns:
        bool: True if version exists, False otherwise
    """
    try:
        # Maven Central REST API
        url = f"https://search.maven.org/solrsearch/select"
        params = {
            "q": f"g:{group_id} AND a:{artifact_id} AND v:{version}",
            "rows": 1,
            "wt": "json"
        }
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        num_found = data.get("response", {}).get("numFound", 0)
        return num_found > 0
    except Exception as e:
        print(f"  ⚠ Could not verify version in Maven Central: {e}")
        return False


def get_latest_versions_from_maven(group_id, artifact_id, limit=10):
    """
    Get the latest versions of a dependency from Maven Central.
    
    Returns:
        list: List of version strings, sorted by newest first
    """
    try:
        url = f"https://search.maven.org/solrsearch/select"
        params = {
            "q": f"g:{group_id} AND a:{artifact_id}",
            "rows": limit,
            "wt": "json",
            "core": "gav"
        }
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        docs = data.get("response", {}).get("docs", [])
        versions = [doc.get("v") for doc in docs if doc.get("v")]
        
        return versions
    except Exception as e:
        print(f"  ⚠ Could not fetch versions from Maven Central: {e}")
        return []


def ai_suggest_safe_version(group_id, artifact_id, current_version, suggested_version, available_versions, pom_content):
    """
    Use AI to suggest a safe version upgrade that exists in Maven Central.
    
    Args:
        group_id: Maven groupId
        artifact_id: Maven artifactId
        current_version: Current version in pom.xml
        suggested_version: Version suggested by scanner (may not exist)
        available_versions: List of versions available in Maven Central
        pom_content: Content of pom.xml for context
    
    Returns:
        str: Recommended version to upgrade to, or None if no safe upgrade found
    """
    # Extract Java version from POM
    java_version_match = re.search(r'<java\.version>([\d.]+)</java\.version>', pom_content)
    java_version = java_version_match.group(1) if java_version_match else "unknown"
    
    # Extract Spring Boot version from POM
    spring_boot_match = re.search(r'<parent>.*?<artifactId>spring-boot-starter-parent</artifactId>.*?<version>([\d.]+)</version>', pom_content, re.DOTALL)
    spring_boot_version = spring_boot_match.group(1) if spring_boot_match else "unknown"
    
    # Check if GITHUB_TOKEN is available for AI features
    if not GITHUB_TOKEN:
        print(f"  ⚠ GITHUB_TOKEN not set - falling back to newest stable version")
        print(f"  ℹ Java version: {java_version}, Spring Boot: {spring_boot_version}")
        # Fall back to newest stable version without AI
        for v in available_versions:
            if not any(x in v.lower() for x in ['alpha', 'beta', 'rc', 'snapshot', 'm1', 'm2']):
                print(f"  ✓ Selected newest stable version: {v}")
                return v
        return None
    
    print(f"  → AI analyzing safe upgrade path for {group_id}:{artifact_id}...")
    print(f"  ℹ Constraints: Java {java_version}, Spring Boot {spring_boot_version}")
    
    available_versions_str = ", ".join(available_versions[:20]) if available_versions else "None found"
    
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a Maven dependency expert. Your job is to recommend a safe version upgrade.\n\n"
                    "CRITICAL RULES:\n"
                    "1. ONLY recommend versions that exist in the 'Available versions' list\n"
                    "2. Prefer stable releases (avoid alpha, beta, RC, SNAPSHOT)\n"
                    "3. Choose the newest stable version that fixes the vulnerability\n"
                    "4. RESPECT Java version constraints - if Java 8, avoid versions requiring Java 11+\n"
                    "5. RESPECT Spring Boot version constraints:\n"
                    "   - Spring Boot 2.x (Java 8-17): Use Spring Framework 5.3.x, not 6.x\n"
                    "   - Spring Boot 3.x (Java 17+): Use Spring Framework 6.x\n"
                    "6. For Spring dependencies, stay within the same major version family\n"
                    "7. If the scanner's suggested version doesn't exist or is incompatible, find the closest compatible alternative\n"
                    "8. Return ONLY the version number (e.g., '2.7.18' or '5.3.31'), nothing else\n"
                    "9. If no safe upgrade exists within compatibility constraints, return 'SKIP'\n\n"
                    "Output format: Just the version number or 'SKIP'"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Dependency: {group_id}:{artifact_id}\n"
                    f"Current version: {current_version or 'unknown'}\n"
                    f"Scanner suggested version: {suggested_version}\n"
                    f"Available versions in Maven Central: {available_versions_str}\n\n"
                    f"PROJECT CONSTRAINTS:\n"
                    f"Java version: {java_version}\n"
                    f"Spring Boot version: {spring_boot_version}\n\n"
                    f"POM context (first 1000 chars):\n{pom_content[:1000]}\n\n"
                    f"What version should we upgrade to that is compatible with Java {java_version} and Spring Boot {spring_boot_version}?"
                ),
            },
        ],
        "temperature": 0,
    }

    try:
        result = call_with_retry(_post_to_api, payload)
        recommendation = result["choices"][0]["message"]["content"].strip()
        
        # Clean up the response
        recommendation = re.sub(r"```.*?```", "", recommendation, flags=re.DOTALL)
        recommendation = recommendation.strip()
        
        # Validate the recommendation
        if recommendation == "SKIP":
            print(f"  ✗ AI recommends skipping this upgrade (no compatible version found)")
            print(f"  ℹ Consider upgrading to Java 11 or 17 to access newer dependency versions")
            return None
        
        # Check if recommended version is in available versions
        if recommendation in available_versions:
            print(f"  ✓ AI recommends version: {recommendation} (compatible with Java {java_version})")
            return recommendation
        else:
            print(f"  ⚠ AI suggested {recommendation} but it's not in available versions")
            # Fall back to the newest stable version
            for v in available_versions:
                if not any(x in v.lower() for x in ['alpha', 'beta', 'rc', 'snapshot', 'm1', 'm2']):
                    print(f"  ✓ Falling back to newest stable: {v}")
                    return v
            return None
            
    except Exception as e:
        print(f"  ✗ AI version suggestion failed: {e}")
        # Fall back to newest stable version
        for v in available_versions:
            if not any(x in v.lower() for x in ['alpha', 'beta', 'rc', 'snapshot', 'm1', 'm2']):
                print(f"  ✓ Falling back to newest stable: {v}")
                return v
        return None


def _post_to_api(payload):
    """Raw API call to GitHub Models."""
    response = requests.post(
        "https://models.github.ai/inference/chat/completions",
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload),
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def extract_dependency_info(finding):
    """
    Extract dependency information from normalized finding format.
    
    This function handles both old and new normalized schema formats:
    - Old format: {"package": "groupId:artifactId", "recommended_fix_version": "1.2.3"}
    - New format: {"package_name": "groupId:artifactId", "current_version": "1.0.0", "fixed_version": "1.2.3"}
    
    Args:
        finding: Dictionary containing vulnerability finding
    
    Returns:
        Tuple of (package_name, current_version, fixed_version) or None if invalid
    """
    # Try new normalized schema format first
    package_name = finding.get("package_name")
    current_version = finding.get("current_version")
    fixed_version = finding.get("fixed_version")
    
    # Fall back to old format for backward compatibility
    if not package_name:
        package_name = finding.get("package")
    
    if not fixed_version:
        fixed_version = finding.get("recommended_fix_version")
    
    # Validate we have required fields
    if not package_name or not fixed_version:
        return None
    
    # Skip if fixed_version is "unknown" (no fix available)
    if fixed_version == "unknown":
        return None
    
    return (package_name, current_version, fixed_version)


def main():
    """Main entry point for the script."""
    # Read the JSON vulnerability report
    report_file = safe_path(sys.argv[1])
    pom_file = safe_path(sys.argv[2])
    with open(report_file) as f:
        data = json.load(f)

    # Read pom.xml content for AI context
    with open(pom_file) as f:
        pom_content = f.read()

    # Extract dependency vulnerabilities from normalized schema
    # The normalized schema has findings in "dependency_vulnerabilities" array
    dependencies = data.get("dependency_vulnerabilities", [])

    # Parse pom.xml
    tree = parse(pom_file)
    root = tree.getroot()
    namespaces = {'m': 'http://maven.apache.org/POM/4.0.0'}

    # Track statistics
    total_findings = len(dependencies)
    skipped_count = 0
    updated_count = 0
    not_found_count = 0
    ai_corrected_count = 0

    print(f"Processing {total_findings} dependency vulnerabilities...")
    print("Using AI to validate versions and suggest safe upgrades...\n")

    for dep in dependencies:
        # Extract dependency info from normalized schema
        dep_info = extract_dependency_info(dep)
        if not dep_info:
            skipped_count += 1
            continue
        
        package_name, current_version, scanner_suggested_version = dep_info
        
        # Parse package name (format: "groupId:artifactId")
        group_artifact = package_name.split(":")
        if len(group_artifact) != 2:
            print(f"Warning: Invalid package format '{package_name}', expected 'groupId:artifactId'")
            skipped_count += 1
            continue
        
        group_id, artifact_id = group_artifact
        
        # Log what we're processing
        print(f"\n{'='*70}")
        print(f"Processing: {group_id}:{artifact_id}")
        print(f"  Current version: {current_version if current_version else 'unknown'}")
        print(f"  Scanner suggested: {scanner_suggested_version}")

        # Step 1: Check if scanner's suggested version exists in Maven Central
        version_exists = check_maven_central(group_id, artifact_id, scanner_suggested_version)
        
        if version_exists:
            print(f"  ✓ Scanner version verified in Maven Central")
            final_version = scanner_suggested_version
        else:
            print(f"  ✗ Scanner version NOT found in Maven Central")
            print(f"  → Fetching available versions from Maven Central...")
            
            # Step 2: Get available versions from Maven Central
            available_versions = get_latest_versions_from_maven(group_id, artifact_id, limit=20)
            
            if not available_versions:
                print(f"  ✗ Could not fetch versions from Maven Central, skipping")
                skipped_count += 1
                continue
            
            print(f"  → Found {len(available_versions)} versions in Maven Central")
            
            # Step 3: Use AI to suggest a safe version
            final_version = ai_suggest_safe_version(
                group_id, 
                artifact_id, 
                current_version, 
                scanner_suggested_version,
                available_versions,
                pom_content
            )
            
            if not final_version:
                print(f"  ✗ No safe upgrade version found, skipping")
                skipped_count += 1
                continue
            
            ai_corrected_count += 1
            print(f"  ✓ AI corrected version: {scanner_suggested_version} → {final_version}")

        # Step 4: Apply the version update
        print(f"  → Applying version update to {final_version}...")
        
        updated = False
        for dependency in root.findall(".//m:dependency", namespaces):
            group_elem = dependency.find("m:groupId", namespaces)
            artifact_elem = dependency.find("m:artifactId", namespaces)
            version_elem = dependency.find("m:version", namespaces)

            if group_elem is None or artifact_elem is None or version_elem is None:
                continue

            group = group_elem.text.strip()
            artifact = artifact_elem.text.strip()
            version_text = version_elem.text.strip()

            if group == group_id and artifact == artifact_id:
                try:
                    if version_text.startswith("${") and version_text.endswith("}"):
                        # Version is a property like ${spring.version}
                        property_name = version_text[2:-1]
                        print(f"  → Updating property {property_name} to {final_version}")
                        result = subprocess.run([
                            "mvn", "versions:set-property",
                            f"-Dproperty={property_name}",
                            f"-DnewVersion={final_version}",
                            "-DforceVersion=true"
                        ], capture_output=True, text=True, check=False)
                        
                        if result.returncode == 0:
                            print(f"  ✓ Property updated successfully")
                            updated = True
                        else:
                            print(f"  ✗ Maven command failed: {result.stderr[:200]}")
                    else:
                        # Version is explicit
                        print(f"  → Updating {group_id}:{artifact_id} to {final_version}")
                        result = subprocess.run([
                            "mvn", "versions:use-dep-version",
                            f"-Dincludes={group_id}:{artifact_id}",
                            f"-DdepVersion={final_version}",
                            "-DforceVersion=true"
                        ], capture_output=True, text=True, check=False)
                        
                        if result.returncode == 0:
                            print(f"  ✓ Dependency updated successfully")
                            updated = True
                        else:
                            print(f"  ✗ Maven command failed: {result.stderr[:200]}")
                    
                    if updated:
                        updated_count += 1
                    break
                    
                except Exception as e:
                    print(f"  ✗ Error updating dependency: {e}")

        if not updated:
            print(f"  ⚠ Dependency {group_id}:{artifact_id} not found in pom.xml or update failed")
            not_found_count += 1
        
        # Small delay to avoid rate limiting
        time.sleep(0.5)

    # Commit all changes to pom.xml
    print(f"\n{'='*70}")
    print("Committing changes to pom.xml...")
    try:
        subprocess.run(["mvn", "versions:commit"], check=True, capture_output=True)
        print("✓ Changes committed successfully")
    except subprocess.CalledProcessError as e:
        print(f"⚠ Warning: Could not commit changes: {e}")

    # Print summary
    print(f"\n{'='*70}")
    print("Dependency Update Summary")
    print(f"{'='*70}")
    print(f"Total findings processed:        {total_findings}")
    print(f"Successfully updated:            {updated_count}")
    print(f"AI-corrected versions:           {ai_corrected_count}")
    print(f"Skipped (no fix available):      {skipped_count}")
    print(f"Not found in pom.xml:            {not_found_count}")
    print(f"{'='*70}")

    if updated_count > 0:
        print("✅ Dependency updates completed!")
        if ai_corrected_count > 0:
            print(f"   AI corrected {ai_corrected_count} invalid scanner suggestions")
    else:
        print("⚠️  No dependencies were updated.")
    
    print("\nNext steps:")
    print("  1. Run: mvn clean compile")
    print("  2. Verify the build succeeds")
    print("  3. Run tests to ensure compatibility")


if __name__ == "__main__":
    main()
