#!/usr/bin/env python3
"""
Create Jira ticket using direct REST API calls (alternative to JIRA library).

This script uses requests library directly instead of the jira library,
which can help when the jira library has authentication or URL issues.

Usage:
    python create_jira_direct.py <normalized_json>
"""

import json
import sys
import os
import requests
from requests.auth import HTTPBasicAuth

PROJECT_KEY = "SCRUM"  # Change this to your project key

BASE_DIR = os.getcwd()

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)


def load_scan(json_file):
    """Load scan results from JSON file."""
    with open(json_file) as f:
        return json.load(f)


def build_summary(scan):
    """Build summary text for Jira ticket."""
    dep_vulns = scan.get("dependency_vulnerabilities", [])
    code_vulns = scan.get("code_vulnerabilities", [])
    
    # Detect format
    is_new_format = False
    if dep_vulns and isinstance(dep_vulns[0], dict):
        if "package_name" in dep_vulns[0] or "scanner" in dep_vulns[0]:
            is_new_format = True
    
    if is_new_format:
        dep_count = len(dep_vulns)
        code_count = len(code_vulns)
    else:
        dep_count = sum(len(d.get("vulnerabilities", [])) for d in dep_vulns)
        code_count = len(code_vulns)

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


def create_jira_ticket_direct(json_file):
    """
    Create Jira ticket using direct REST API calls.
    
    This bypasses the jira library and uses requests directly,
    which can help with authentication and URL issues.
    """
    # Get environment variables
    jira_url = os.environ.get('JIRA_URL', '').rstrip('/')
    jira_email = os.environ.get('JIRA_EMAIL', '')
    jira_token = os.environ.get('JIRA_API_TOKEN', '')
    
    if not all([jira_url, jira_email, jira_token]):
        print("Error: Missing required environment variables")
        print(f"  JIRA_URL: {'✓' if jira_url else '✗'}")
        print(f"  JIRA_EMAIL: {'✓' if jira_email else '✗'}")
        print(f"  JIRA_API_TOKEN: {'✓' if jira_token else '✗'}")
        sys.exit(1)
    
    # Clean URL if needed
    if '/rest/api' in jira_url:
        jira_url = jira_url.split('/rest/api')[0]
    
    print("=" * 60)
    print("JIRA TICKET CREATION (Direct REST API)")
    print("=" * 60)
    print(f"Jira URL: {jira_url}")
    print(f"Email: {jira_email}")
    print(f"Project: {PROJECT_KEY}")
    
    # Load scan data
    scan = load_scan(json_file)
    description = build_summary(scan)
    scanner = scan['scan_metadata'].get('scanner', 'snyk')
    
    # Build labels
    labels = ["security", "auto-scan"]
    if "snyk" in scanner.lower():
        labels.append("snyk")
    if "inspector" in scanner.lower():
        labels.append("inspector")
        labels.append("aws")
    
    # Prepare authentication
    auth = HTTPBasicAuth(jira_email, jira_token)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    # Test connection first using API v3
    print("\nTesting connection...")
    try:
        response = requests.get(
            f"{jira_url}/rest/api/3/myself",  # Use API v3
            auth=auth,
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            user_info = response.json()
            print(f"✓ Authenticated as: {user_info.get('displayName', 'Unknown')}")
        else:
            print(f"✗ Authentication failed: {response.status_code}")
            print(f"  Response: {response.text}")
            sys.exit(1)
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        sys.exit(1)
    
    # Create issue payload
    issue_data = {
        "fields": {
            "project": {
                "key": PROJECT_KEY
            },
            "summary": f"Security Scan Findings ({scanner}) - {scan['scan_metadata']['project']}",
            "description": description,
            "issuetype": {
                "name": "Task"
            },
            "labels": labels
        }
    }
    
    print(f"\nCreating issue in project {PROJECT_KEY}...")
    print(f"  Issue type: Task")
    print(f"  Labels: {', '.join(labels)}")
    
    # Create the issue using API v3 (matching your curl command)
    try:
        response = requests.post(
            f"{jira_url}/rest/api/3/issue",  # Use API v3
            auth=auth,
            headers=headers,
            json=issue_data,
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            issue = response.json()
            issue_key = issue.get('key')
            print(f"✓ Issue created: {issue_key}")
            
            # Add attachment
            print(f"\nAttaching scan data...")
            with open(json_file, 'rb') as f:
                files = {
                    'file': ('scan_payload.json', f, 'application/json')
                }
                attach_headers = {
                    "X-Atlassian-Token": "no-check"
                }
                
                attach_response = requests.post(
                    f"{jira_url}/rest/api/3/issue/{issue_key}/attachments",  # Use API v3
                    auth=auth,
                    headers=attach_headers,
                    files=files,
                    timeout=30
                )
                
                if attach_response.status_code in [200, 201]:
                    print(f"✓ Attachment added successfully")
                else:
                    print(f"⚠ Warning: Could not add attachment: {attach_response.status_code}")
                    print(f"  Response: {attach_response.text}")
            
            print("=" * 60)
            print(f"SUCCESS: Ticket {issue_key} created!")
            print(f"URL: {jira_url}/browse/{issue_key}")
            print("=" * 60)
            
        else:
            print(f"✗ Failed to create issue: {response.status_code}")
            print(f"  Response: {response.text}")
            
            # Parse error details
            try:
                error_data = response.json()
                if 'errors' in error_data:
                    print("\n  Error details:")
                    for field, error in error_data['errors'].items():
                        print(f"    {field}: {error}")
                if 'errorMessages' in error_data:
                    print("\n  Error messages:")
                    for msg in error_data['errorMessages']:
                        print(f"    - {msg}")
            except:
                pass
            
            sys.exit(1)
            
    except Exception as e:
        print(f"✗ Error creating issue: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python create_jira_direct.py <normalized_json>")
        sys.exit(1)

    json_file = safe_path(sys.argv[1])

    # Validate file exists
    if not os.path.isfile(json_file):
        print(f"File not found: {json_file}")
        sys.exit(1)

    create_jira_ticket_direct(json_file)
