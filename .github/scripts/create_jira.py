import json
from jira import JIRA
import sys
import os

PROJECT_KEY = "SCRUM"

BASE_DIR = os.getcwd()

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)



def connect_jira():
    """
    Connect to Jira using environment variables.
    
    Forces API v3 since Jira Cloud permissions are configured for v3.
    """
    jira_url = os.environ.get('JIRA_URL', '').rstrip('/')
    
    # Strip any /rest/api/* paths - we'll specify the version explicitly
    if '/rest/api' in jira_url:
        jira_url = jira_url.split('/rest/api')[0]
    
    # Force API v3 - Jira Cloud uses v3, and permissions are configured there
    return JIRA(
        server=jira_url,
        basic_auth=(os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN")),
        options={'rest_api_version': '3'}
    )


def load_scan(json_file):
    """
    Load scan results from JSON file.
    
    Supports both old Snyk format and new normalized schema format.
    
    Returns:
        Dictionary containing scan data
    """
    with open(json_file) as f:
        return json.load(f)


def build_summary(scan):
    """
    Build summary text for Jira ticket.
    
    Supports both old Snyk format and new normalized schema format.
    
    Old format:
        - dependency_vulnerabilities: list of objects with "package", "vulnerabilities" list
        - code_vulnerabilities: list of objects with "rule_id", "occurrences" list
    
    New format:
        - dependency_vulnerabilities: list of NormalizedFinding objects
        - code_vulnerabilities: list of NormalizedFinding objects
    
    Args:
        scan: Dictionary containing scan results
    
    Returns:
        Formatted summary string for Jira ticket description
    """
    dep_vulns = scan.get("dependency_vulnerabilities", [])
    code_vulns = scan.get("code_vulnerabilities", [])
    
    # Detect format by checking structure of first dependency vulnerability
    is_new_format = False
    if dep_vulns and isinstance(dep_vulns[0], dict):
        # Check if it has new format fields (package_name, scanner, etc.)
        if "package_name" in dep_vulns[0] or "scanner" in dep_vulns[0]:
            is_new_format = True
    
    if is_new_format:
        # New normalized format: each item is a single finding
        dep_count = len(dep_vulns)
        code_count = len(code_vulns)
    else:
        # Old format: each item contains multiple vulnerabilities
        dep_count = sum(len(d.get("vulnerabilities", [])) for d in dep_vulns)
        code_count = len(code_vulns)  # Code vulns are already individual items in old format

    summary = f"""
Security Scan Report

Project: {scan['scan_metadata']['project']}
Repository: {scan['scan_metadata']['repository']}
Branch: {scan['scan_metadata']['branch']}
Scanner: {scan['scan_metadata']['scanner']}

Summary
-------
Dependency vulnerabilities detected: {dep_count}
Code vulnerabilities detected: {code_count}

Full vulnerability details are attached in scan_payload.json.
AI remediation planner will analyze the attachment and suggest fixes.
"""

    return summary.strip()


def create_jira_ticket(json_file):
    """
    Create Jira ticket for security scan findings.
    
    Supports both old Snyk format and new normalized schema format.
    Includes scanner source in ticket summary and labels.
    
    Args:
        json_file: Path to JSON file containing scan results
    """
    jira = connect_jira()
    scan = load_scan(json_file)

    description = build_summary(scan)
    
    # Get scanner name from metadata
    scanner = scan['scan_metadata'].get('scanner', 'snyk')
    
    # Build labels based on scanner
    labels = ["security", "auto-scan"]
    
    # Add scanner-specific labels
    if "snyk" in scanner.lower():
        labels.append("snyk")
    if "inspector" in scanner.lower():
        labels.append("inspector")
        labels.append("aws")

    issue_dict = {
        "project": {"key": PROJECT_KEY},
        "summary": f"Security Scan Findings ({scanner}) - {scan['scan_metadata']['project']}",
        "description": {
        "type": "doc",
        "version": 1,
        "content": [
        {
            "type": "paragraph",
            "content": [
                {
                    "type": "text",
                    "text": description  # Ensure 'description' is plain text
                }
            ]
        }
        ]
    },
    "issuetype": {"name": "Task"},
    "labels": labels
    }
    issue = jira.create_issue(fields=issue_dict)

    print("Jira ticket created:", issue.key)

    with open(json_file, "rb") as f:
        jira.add_attachment(
            issue=issue.key,
            attachment=f,
            filename="scan_payload.json"
        )

    print("JSON attached to ticket.")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python create_jira_issues.py <normalized_json>")
        sys.exit(1)

    json_file = safe_path(sys.argv[1])

    # Validate file exists
    if not os.path.isfile(json_file):
        print(f"File not found: {json_file}")
        sys.exit(1)

    create_jira_ticket(json_file)