import json
from jira import JIRA
import sys
import os

PROJECT_KEY = "SCRUM"  # Change this to a project where you have Create Issues permission
# Examples: "DEV", "SEC", "VULN", etc.

BASE_DIR = os.getcwd()

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)



def connect_jira():
    """
    Connect to Jira using environment variables.
    
    IMPORTANT: JIRA_URL should be the BASE URL only:
    - Correct: https://your-domain.atlassian.net
    - Wrong: https://your-domain.atlassian.net/rest/api/3/issue/
    
    The JIRA library will automatically append the correct API paths.
    
    Returns:
        JIRA client instance
    """
    jira_url = os.environ.get('JIRA_URL', '').rstrip('/')
    jira_email = os.environ.get('JIRA_EMAIL', '')
    jira_token = os.environ.get('JIRA_API_TOKEN', '')
    
    # If URL contains /rest/api, extract only the base URL
    # The JIRA library needs the base URL and will add API paths automatically
    if '/rest/api' in jira_url:
        base_url = jira_url.split('/rest/api')[0]
        print(f"Warning: JIRA_URL contains API path. Using base URL: {base_url}")
        print(f"Original URL: {jira_url}")
        jira_url = base_url
    
    print(f"Connecting to Jira at: {jira_url}")
    print(f"Using email: {jira_email}")
    print(f"API token length: {len(jira_token)} characters")
    
    # Use API v3 (matching your curl command)
    # The JIRA library defaults to v2, but your permissions are in v3
    try:
        jira = JIRA(
            server=jira_url,
            basic_auth=(jira_email, jira_token),
            options={
                'server': jira_url,
                'rest_api_version': '3',  # Use API v3
                'verify': True
            }
        )
        print("✓ Using Jira REST API v3")
        return jira
    except Exception as e:
        print(f"Error with API v3: {e}")
        print(f"\nTrying API v2 fallback...")
        
        # Fallback to v2
        jira = JIRA(
            server=jira_url,
            basic_auth=(jira_email, jira_token)
        )
        print("✓ Using Jira REST API v2 (fallback)")
        return jira


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
    try:
        print("=" * 60)
        print("JIRA TICKET CREATION")
        print("=" * 60)
        
        jira = connect_jira()
        print("✓ Successfully connected to Jira")
        
        # Test permissions by getting server info
        try:
            server_info = jira.server_info()
            print(f"✓ Jira Server: {server_info.get('serverTitle', 'Unknown')}")
            print(f"✓ Jira Version: {server_info.get('version', 'Unknown')}")
        except Exception as e:
            print(f"⚠ Warning: Could not get server info: {e}")
        
        # Test project access
        try:
            project = jira.project(PROJECT_KEY)
            print(f"✓ Project found: {project.name} ({PROJECT_KEY})")
        except Exception as e:
            print(f"✗ Error: Cannot access project '{PROJECT_KEY}'")
            print(f"  Error details: {e}")
            print(f"\n  Possible causes:")
            print(f"  1. Project key '{PROJECT_KEY}' does not exist")
            print(f"  2. Your account does not have access to this project")
            print(f"  3. API token does not have permission to view projects")
            raise
        
        scan = load_scan(json_file)
        print(f"✓ Loaded scan data from: {json_file}")

        description = build_summary(scan)
        
        # Get scanner name from metadata
        scanner = scan['scan_metadata'].get('scanner', 'snyk')
        print(f"✓ Scanner: {scanner}")
        
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
            "description": description,
            "issuetype": {"name": "Task"},
            "labels": labels
        }

        print(f"\nCreating Jira ticket...")
        print(f"  Project: {PROJECT_KEY}")
        print(f"  Issue Type: Task")
        print(f"  Labels: {', '.join(labels)}")
        
        issue = jira.create_issue(fields=issue_dict)
        print(f"✓ Jira ticket created: {issue.key}")

        print(f"\nAttaching scan data...")
        with open(json_file, "rb") as f:
            jira.add_attachment(
                issue=issue.key,
                attachment=f,
                filename="scan_payload.json"
            )
        print(f"✓ JSON attached to ticket")
        
        print("=" * 60)
        print(f"SUCCESS: Ticket {issue.key} created successfully!")
        print("=" * 60)
        
    except Exception as e:
        print("\n" + "=" * 60)
        print("ERROR CREATING JIRA TICKET")
        print("=" * 60)
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        
        # Print more details if available
        if hasattr(e, 'response'):
            print(f"\nHTTP Response Details:")
            print(f"  Status code: {e.response.status_code}")
            print(f"  Response text: {e.response.text}")
        
        if hasattr(e, 'status_code'):
            print(f"\nStatus code: {e.status_code}")
            
            if e.status_code == 401:
                print("\n⚠ AUTHENTICATION ERROR (401 Unauthorized)")
                print("  Possible causes:")
                print("  1. JIRA_EMAIL is incorrect")
                print("  2. JIRA_API_TOKEN is invalid or expired")
                print("  3. API token was not generated correctly")
                print("\n  Solution:")
                print("  1. Go to: https://id.atlassian.com/manage-profile/security/api-tokens")
                print("  2. Create a new API token")
                print("  3. Update JIRA_API_TOKEN secret in GitHub")
                
            elif e.status_code == 403:
                print("\n⚠ PERMISSION ERROR (403 Forbidden)")
                print("  Possible causes:")
                print(f"  1. Your account cannot create issues in project '{PROJECT_KEY}'")
                print("  2. Your account cannot create 'Task' issue type")
                print("  3. Your account cannot add labels")
                print("  4. Your account cannot add attachments")
                print("\n  Solution:")
                print(f"  1. Verify you have 'Create Issues' permission in project '{PROJECT_KEY}'")
                print("  2. Ask your Jira admin to grant you the necessary permissions")
                print("  3. Try using a different issue type (e.g., 'Bug' instead of 'Task')")
                
            elif e.status_code == 404:
                print("\n⚠ NOT FOUND ERROR (404)")
                print("  Possible causes:")
                print(f"  1. Project '{PROJECT_KEY}' does not exist")
                print("  2. Issue type 'Task' does not exist in this project")
                print("\n  Solution:")
                print("  1. Verify the project key is correct")
                print("  2. Check available issue types in your Jira project")
        
        print("=" * 60)
        raise


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