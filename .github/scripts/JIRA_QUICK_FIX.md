# Jira Connection - Quick Fix

## The Problem

You were using:
```bash
JIRA_URL=https://your-domain.atlassian.net/rest/api/3/issue/
```

This causes the error:
```
"No endpoint GET /rest/api/3/issue/rest/api/2/serverInfo"
```

## Why It Happens

The JIRA Python library **automatically adds** `/rest/api/2/serverInfo` to verify the connection.

When your URL already contains `/rest/api/3/issue/`, it creates:
```
https://domain.atlassian.net/rest/api/3/issue/rest/api/2/serverInfo
                                        ↑                ↑
                                   Your URL        Library adds this
```

## The Fix

### Step 1: Update Your JIRA_URL

Change from:
```bash
JIRA_URL=https://your-domain.atlassian.net/rest/api/3/issue/
```

To:
```bash
JIRA_URL=https://your-domain.atlassian.net
```

### Step 2: Update GitHub Secret

1. Go to your repository **Settings**
2. Click **Secrets and variables** → **Actions**
3. Find `JIRA_URL` secret
4. Click **Update**
5. Set value to: `https://your-domain.atlassian.net` (base URL only)
6. Click **Update secret**

### Step 3: Test

The script now automatically:
- Detects if you included `/rest/api` in the URL
- Extracts the base URL
- Prints a warning
- Uses the correct base URL

You'll see:
```
Warning: JIRA_URL contains API path. Using base URL: https://your-domain.atlassian.net
Original URL: https://your-domain.atlassian.net/rest/api/3/issue/
Connecting to Jira at: https://your-domain.atlassian.net
Creating Jira ticket in project: SCRUM
Jira ticket created: SCRUM-123
```

## What About API v3?

The JIRA Python library uses API v2 by default, which is compatible with Jira Cloud. The library automatically:
- Uses v2 for most operations (standard)
- Uses v3 for newer features (when needed)
- Handles all API versioning internally

You don't need to specify the API version in the URL.

## Still Having Issues?

If you still get permission errors after fixing the URL:

1. **Check API Token**: Generate a new one at https://id.atlassian.com/manage-profile/security/api-tokens
2. **Check Permissions**: Verify your account can create issues in the project
3. **Check Project Key**: Verify `PROJECT_KEY = "SCRUM"` matches your project

---

**TL;DR**: Use `https://your-domain.atlassian.net` (base URL only) for `JIRA_URL`
