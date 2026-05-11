import json
import subprocess
import sys
from defusedxml.ElementTree import parse   
import os


BASE_DIR = os.getcwd()

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)


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

    print(f"Processing {total_findings} dependency vulnerabilities...")

    for dep in dependencies:
        # Extract dependency info from normalized schema
        dep_info = extract_dependency_info(dep)
        if not dep_info:
            skipped_count += 1
            continue
        
        package_name, current_version, fixed_version = dep_info
        
        # Parse package name (format: "groupId:artifactId")
        group_artifact = package_name.split(":")
        if len(group_artifact) != 2:
            print(f"Warning: Invalid package format '{package_name}', expected 'groupId:artifactId'")
            skipped_count += 1
            continue
        
        group_id, artifact_id = group_artifact
        
        # Log what we're processing
        print(f"\nProcessing: {group_id}:{artifact_id}")
        print(f"  Current version: {current_version if current_version else 'unknown'}")
        print(f"  Fixed version: {fixed_version}")

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
                if version_text.startswith("${") and version_text.endswith("}"):
                    # Version is a property like ${spring.version}
                    property_name = version_text[2:-1]
                    print(f"  Updating property {property_name} to {fixed_version}")
                    subprocess.run([
                        "mvn", "versions:set-property",
                        f"-Dproperty={property_name}",
                        f"-DnewVersion={fixed_version}",
                        "-DforceVersion=true"
                    ], check=True)
                else:
                    # Version is explicit
                    print(f"  Updating {group_id}:{artifact_id} to {fixed_version}")
                    subprocess.run([
                        "mvn", "versions:use-dep-version",
                        f"-Dincludes={group_id}:{artifact_id}",
                        f"-DdepVersion={fixed_version}",
                        "-DforceVersion=true"
                    ], check=True)

                updated = True
                updated_count += 1
                break

        if not updated:
            print(f"  Warning: Dependency {group_id}:{artifact_id} not found in pom.xml, skipping.")
            not_found_count += 1

    # Commit all changes to pom.xml
    subprocess.run(["mvn", "versions:commit"], check=True)

    # Print summary
    print("\n" + "="*60)
    print("Dependency Update Summary")
    print("="*60)
    print(f"Total findings processed: {total_findings}")
    print(f"Successfully updated: {updated_count}")
    print(f"Skipped (no fix available): {skipped_count}")
    print(f"Not found in pom.xml: {not_found_count}")
    print("="*60)

    if updated_count > 0:
        print("✅ All dependency updates committed successfully!")
    else:
        print("⚠️  No dependencies were updated.")


if __name__ == "__main__":
    main()
