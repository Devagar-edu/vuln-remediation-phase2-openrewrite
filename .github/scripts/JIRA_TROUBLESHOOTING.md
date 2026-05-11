# Jira Integration Troubleshooting Guide

## Understanding the JIRA Python Library

The JIRA Python library **automatically** calls `/rest/api/2/serverInfo` when you initialize it to verify the connection. This is why you cannot include API paths in the `JIRA_URL`.

### How It Works

```python
# When you do this:
JIRA(server="https://domain.atlassian.net")

# The library automatically calls:
# 1. https://domain.atlassian.net/rest/api/2/serverInfo (to verify connection)
# 2. https://domain.atlassian.net/rest/api/2/issue (to create issues)
# 3. https://domain.atlassian.net/rest/api/2/issue/{key}/attachments (to add attachments)
```

### Why Your URL Was Failing

```python
# If you set:
JIRA_URL=https://domain.atlassian.net/rest/api/3/issue/

# The library tries to call:
# https://domain.atlassian.net/rest/api/3/issue/rest/api/2/serverInfo
#                                              ^^^^^^^^^^^^^^^^^^^^
#                                              Library appends this
# Result: 404 Not Found
```

## Solution

### ✅ Correct JIRA_URL Format

**Use the BASE URL only:**
```bash
JIRA_URL=https://your-domain.atlassian.net
```

The JIRA library will automatically:
- Use `/rest/api/2/` for most operations (default)
- Use `/rest/api/3/` for newer features (when needed)
- Handle all API path construction

### ❌ Incorrect JIRA_URL Format

```bash
# Wrong - Contains API path
JIRA_URL=https://your-domain.atlassian.net/rest/api/2

# Wrong - Contains API path
JIRA_URL=https://your-domain.atlassian.net/rest/api/3

# Wrong - Contains specific endpoint
JIRA_URL=https://your-domain.atlassian.net/rest/api/3/issue/
```

### Fix Applied

The `create_jira.py` script now automatically:
1. Strips trailing slashes from `JIRA_URL`
2. Removes any `/rest/api` paths if accidentally included
3. Prints the cleaned URL for debugging

```python
def connect_jira():
    jira_url = os.environ.get('JIRA_URL', '').rstrip('/')
    
    # Remove any API paths if accidentally included
    if '/rest/api' in jira_url:
        jira_url = jira_url.split('/rest/api')[0]
    
    print(f"Connecting to Jira at: {jira_url}")
    
    return JIRA(
        server=jira_url,
        basic_auth=(os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN"))
    )
```

## How to Fix Your Environment

### Option 1: Update GitHub Secrets

1. Go to your repository settings
2. Navigate to **Secrets and variables** → **Actions**
3. Find the `JIRA_URL` secret
4. Update it to contain **only the base URL**:
   ```
   https://your-domain.atlassian.net
   ```

### Option 2: Update Workflow File

If you're setting the environment variable in the workflow:

```yaml
# Before (WRONG)
env:
  JIRA_URL: https://your-domain.atlassian.net/rest/api/2

# After (CORRECT)
env:
  JIRA_URL: https://your-domain.atlassian.net
```

## Verification

After fixing the `JIRA_URL`, you should see this output:
```
Connecting to Jira at: https://your-domain.atlassian.net
Creating Jira ticket in project: SCRUM
Jira ticket created: SCRUM-123
JSON attached to ticket.
```

## Other Common Issues

### Issue: Authentication Failed

**Error**: `401 Unauthorized`

**Solution**:
1. Verify `JIRA_EMAIL` is correct
2. Verify `JIRA_API_TOKEN` is a valid API token (not password)
3. Generate new API token at: https://id.atlassian.com/manage-profile/security/api-tokens

### Issue: Project Not Found

**Error**: `Project 'SCRUM' does not exist`

**Solution**:
1. Verify the project key in `create_jira.py`:
   ```python
   PROJECT_KEY = "SCRUM"  # Change to your project key
   ```
2. Check project exists in Jira
3. Verify you have permission to create issues in the project

### Issue: Issue Type Not Found

**Error**: `Issue type 'Task' does not exist`

**Solution**:
Update the issue type in `create_jira.py`:
```python
issue_dict = {
    "project": {"key": PROJECT_KEY},
    "summary": f"Security Scan Findings...",
    "description": description,
    "issuetype": {"name": "Bug"},  # or "Story", "Epic", etc.
    "labels": labels
}
```

## Debug Mode

To enable detailed debugging, add this to the script:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

This will show all HTTP requests and responses from the JIRA library.

## Testing Connection

Test your Jira connection with this simple script:

```python
import os
from jira import JIRA

jira_url = os.environ.get('JIRA_URL', '').rstrip('/').split('/rest/api')[0]
print(f"Testing connection to: {jira_url}")

jira = JIRA(
    server=jira_url,
    basic_auth=(os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN"))
)

# Test connection
server_info = jira.server_info()
print(f"Connected successfully!")
print(f"Jira version: {server_info['version']}")
print(f"Server title: {server_info['serverTitle']}")
```

## Support

If issues persist:
1. Check the error output for specific details
2. Verify all environment variables are set correctly
3. Test with the connection script above
4. Check Jira API documentation: https://developer.atlassian.com/cloud/jira/platform/rest/v3/

---

**Last Updated**: 2026-05-12  
**Status**: Fixed in create_jira.py
