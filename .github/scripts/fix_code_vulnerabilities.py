"""
AI-powered code vulnerability remediation script.

This script processes code vulnerability findings and uses AI to generate fixes.
It supports both the legacy Snyk format and the new normalized schema format.

Normalized Schema Support:
- Reads code_vulnerabilities from normalized findings format
- Extracts file paths, line numbers, and vulnerability details from metadata
- Maintains backward compatibility with existing Snyk workflow

Usage:
    python fix_code_vulnerabilities.py <report_file>
    
    report_file: Path to JSON file containing vulnerability findings
                 (supports both old Snyk format and new normalized format)

Requirements: 6.1, 6.2, 9.4
"""

import json
import time
import requests
import os
import sys
import re
import difflib
from collections import defaultdict

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN environment variable not set")

BASE_DIR = os.getcwd()

def safe_path(user_input):
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)

SNYK_REPORT_FILE = safe_path(sys.argv[1])

MAX_RETRIES = 5

# ---------------------------------------------------------------------------
# Vulnerability fix guidance
# Each entry maps a Snyk rule/title keyword to:
#   "guidance"    — exact instruction for the AI
#   "new_files"   — companion files the fix requires (generated separately)
#   "bad_patterns"— code patterns that prove the fix was NOT applied
#   "good_patterns"— code patterns that prove the fix WAS applied
# ---------------------------------------------------------------------------
VULN_CATALOGUE = {
    "sql-injection": {
        "guidance": (
            "Replace every string-concatenated SQL query with a PreparedStatement. "
            "Use '?' placeholders and set values with setString/setInt/etc. "
            "Never concatenate user input directly into a SQL string."
        ),
        "bad_patterns":  [r'"\s*\+\s*\w+', r"'\s*\+\s*\w+"],
        "good_patterns": [r"PreparedStatement", r"setString\(", r"setInt\("],
    },
    "command-injection": {
        "guidance": (
            "Replace Runtime.exec(String) with ProcessBuilder(List<String>). "
            "Split the command into a string array so the OS never interprets shell metacharacters. "
            "Never pass unsanitised user input as a single shell string."
        ),
        "bad_patterns":  [r"Runtime\.getRuntime\(\)\.exec\(", r"exec\(\w+\)"],
        "good_patterns": [r"ProcessBuilder", r"new ArrayList"],
    },
    "path-traversal": {
        "guidance": (
            "After constructing the file path, call toRealPath() or getCanonicalPath() "
            "and verify it still starts with the allowed base directory. "
            "Throw an exception if the resolved path escapes the base."
        ),
        "bad_patterns":  [r"new File\(\w+\)", r"Paths\.get\(\w+\)"],
        "good_patterns": [r"getCanonicalPath\(\)", r"toRealPath\(\)", r"startsWith\("],
    },
    "xxe": {
        "guidance": (
            "On every DocumentBuilderFactory, SAXParserFactory, or XMLInputFactory instance, "
            "disable DOCTYPE declarations and external entity processing:\n"
            "  factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
            "  factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
            "  factory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n"
            "  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");\n"
            "  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, \"\");"
        ),
        "bad_patterns":  [r"DocumentBuilderFactory\.newInstance\(\)", r"SAXParserFactory\.newInstance\(\)"],
        "good_patterns": [r"disallow-doctype-decl", r"external-general-entities", r"ACCESS_EXTERNAL_DTD"],
    },
    "deserialization": {
        "guidance": (
            "Do NOT pass raw HTTP request body directly into any XML/Java deserializer. "
            "Before deserializing, strip DOCTYPE declarations with: "
            "  xml = xml.replaceAll(\"(?i)<!DOCTYPE[^>]*>\", \"\"); "
            "Then configure the parser with secure features (disable external entities). "
            "If the payload is XStream/Java serialization, use a whitelist filter."
        ),
        "bad_patterns":  [r"fromXML\(", r"readObject\(", r"deserialize\("],
        "good_patterns": [r"replaceAll.*DOCTYPE", r"setFeature.*disallow-doctype", r"addPermission"],
    },
"csrf": {
  "guidance": (
    "Fix CSRF vulnerabilities using Spring Security best practices appropriate for production systems. "

    "Decision logic: "
    "1) If the application uses browser-based authentication (cookies, HTTP sessions, form login), "
    "   CSRF protection MUST be enabled and centrally configured using Spring Security. "
    "2) If the application exposes stateless REST APIs secured via Authorization headers "
    "   (JWT, OAuth2, API keys) and does not rely on cookies or server-side sessions, "
    "   CSRF protection is not applicable and MUST NOT be added solely to satisfy a scanner. "

    "Configuration rules: "
    "- Do NOT create a new Spring Security configuration if none exists. "
    "- If a Spring Security configuration already exists, update it instead of creating a new one. "
    "- Never inject security configuration code into controller classes. "

    "Implementation safety requirements: "
    "- Do NOT use deprecated APIs such as WebSecurityConfigurerAdapter. "
    "- Do NOT create empty or comment-only lambda expressions. "
    "- Only use executable configuration calls (e.g., method references or explicit API calls). "
    "- Do NOT embed property placeholders (${...}) inside Java collection literals. "

    "CORS hardening rules: "
    "- CORS configurations MUST NOT use wildcard origins (*) in production. "
    "- Allowed origins MUST be externalized to configuration properties when applicable. "

    "The remediation must compile successfully, preserve existing behavior, and improve security posture "
    "without altering business logic or request semantics."
  ),

  "bad_patterns": [
    "@CrossOrigin\\(origins\\s*=\\s*\"\\*\"",
    "WebSecurityConfigurerAdapter",
    "HttpSecurity",
    "SecurityFilterChain",
    "\\.csrf\\(",
    "public\\s+class\\s+SecurityConfig"
  ],

  "good_patterns": [
    "@RestController",
    "@RequestMapping",
    "@PostMapping",
    "@CrossOrigin\\(origins\\s*=\\s*\"\\$\\{.*\\}\"\\)"
  ],

  "new_files": []
},

    "cors": {
        "guidance": (
            "Replace @CrossOrigin(origins = \"*\") with @CrossOrigin(origins = \"${app.cors.allowed-origins}\"). "
            "Define app.cors.allowed-origins in application.properties with the specific allowed domain. "
            "Never use a wildcard in production."
        ),
        "bad_patterns":  [r'@CrossOrigin\(origins\s*=\s*"\*"'],
        "good_patterns": [r'@CrossOrigin\(origins\s*=\s*"\$\{'],
    },
    "xss": {
        "guidance": (
            "HTML-encode all user-supplied values before writing them to the response. "
            "Use org.owasp.encoder.Encode.forHtml(value) or StringEscapeUtils.escapeHtml4(value). "
            "Never write raw request parameters into HTML responses."
        ),
        "bad_patterns":  [r"getParameter\(", r"println\(.*getParameter"],
        "good_patterns": [r"forHtml\(", r"escapeHtml4\("],
    },
    "hardcoded-secret": {
        "guidance": (
            "Remove the hardcoded credential/key from source code entirely. "
            "Replace it with System.getenv(\"SECRET_NAME\") or a @Value(\"${secret.name}\") "
            "injection from application.properties / environment variables."
        ),
        "bad_patterns":  [r'password\s*=\s*"[^"]+"', r'secret\s*=\s*"[^"]+"'],
        "good_patterns": [r"System\.getenv\(", r"@Value\("],
    },
    "insecure-random": {
        "guidance": (
            "Replace java.util.Random with java.security.SecureRandom for any token, "
            "session ID, nonce, or cryptographic value."
        ),
        "bad_patterns":  [r"new Random\(\)"],
        "good_patterns": [r"new SecureRandom\(\)"],
    },
    "weak-cryptography": {
        "guidance": (
            "Replace MD5/SHA1 with SHA-256 (MessageDigest.getInstance(\"SHA-256\")). "
            "Replace DES/RC4/3DES with AES-256 in GCM mode "
            "(Cipher.getInstance(\"AES/GCM/NoPadding\"))."
        ),
        "bad_patterns":  [r'"MD5"', r'"SHA-1"', r'"SHA1"', r'"DES"'],
        "good_patterns": [r'"SHA-256"', r'"AES/GCM'],
    },
    "ssrf": {
        "guidance": (
            "Before making any outbound HTTP request with user-supplied URL/host, "
            "parse the URL and validate the host against a strict allowlist. "
            "Reject private IP ranges (10.x, 172.16.x, 192.168.x, 127.x) and non-https schemes."
        ),
        "bad_patterns":  [r"new URL\(\w+\)", r"HttpClient.*\w+Url"],
        "good_patterns": [r"allowedHosts\.contains\(", r"ALLOWED_HOSTS"],
    },
    "resource-leak": {
        "guidance": (
            "Wrap every InputStream, OutputStream, Connection, Statement, and ResultSet "
            "in a try-with-resources block so they are closed automatically even on exception."
        ),
        "bad_patterns":  [r"new FileInputStream\((?!.*try)", r"getConnection\((?!.*try)"],
        "good_patterns": [r"try\s*\("],
    },
}

# ---------------------------------------------------------------------------
# Templates for companion files the AI cannot reliably generate inline
# ---------------------------------------------------------------------------
NEW_FILE_TEMPLATES = {
    "SecurityConfig.java": """\
package {package};

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {{

    /**
     * Configure CSRF and CORS.
     * Set app.cors.allowed-origins in application.properties to your real domain.
     * Example:  app.cors.allowed-origins=https://yourdomain.com
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {{
        http
            // Enable CSRF for browser clients; disable only for pure REST APIs consumed by non-browser clients
            .csrf(csrf -> csrf
                // If this is a stateless REST API, you may disable CSRF entirely:
                // .disable()
                // Otherwise keep it enabled (default) and ensure clients send the CSRF token.
            )
            .cors(cors -> cors.configurationSource(corsConfigurationSource()));
        return http.build();
    }}

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {{
        CorsConfiguration config = new CorsConfiguration();
        // TODO: replace with your actual allowed origin from application.properties
        config.setAllowedOrigins(List.of("${{app.cors.allowed-origins:https://yourdomain.com}}"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }}
}}
""",
}


def get_catalogue_entry(vuln):
    rule_id = (vuln.get("rule_id") or vuln.get("id") or "").lower()
    title   = (vuln.get("title")   or vuln.get("type") or "").lower()
    info    = (vuln.get("info")    or vuln.get("description") or "").lower()
    combined = f"{rule_id} {title} {info}"
    for key, entry in VULN_CATALOGUE.items():
        if key in combined:
            return key, entry
    return None, {
        "guidance": vuln.get("description") or vuln.get("info") or
                    "Sanitise all external input and apply the principle of least privilege.",
        "bad_patterns": [],
        "good_patterns": [],
        "new_files": [],
    }


# ---------------------------------------------------------------------------
# Strip AI markdown leakage
# ---------------------------------------------------------------------------
def strip_markdown(text):
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text.strip())
    text = re.sub(r"\n?```$",           "", text.strip())
    return text.strip()


# ---------------------------------------------------------------------------
# Build a precise, line-aware prompt
# ---------------------------------------------------------------------------
def build_prompt(code, vulns, context_files=None):
    lines = code.splitlines()
    vuln_blocks = []

    for i, vuln in enumerate(vulns, 1):
        rule_id  = vuln.get("rule_id") or vuln.get("id") or "UNKNOWN"
        title    = vuln.get("title")   or vuln.get("type") or "Unknown"
        info     = vuln.get("info")    or vuln.get("description") or ""
        _, entry = get_catalogue_entry(vuln)
        guidance = entry["guidance"]

        # Collect affected lines
        affected = []
        for occ in vuln.get("occurrences", []):
            start = occ.get("line_start") or occ.get("line") or occ.get("startLine")
            end   = occ.get("line_end")   or occ.get("endLine") or start
            if start:
                affected.append((int(start), int(end or start)))

        quoted = []
        for s, e in affected:
            for ln in range(max(1, s - 1), min(len(lines), e + 2)):
                quoted.append(f"  Line {ln}: {lines[ln-1]}")
        location_block = "\n".join(quoted) if quoted else "  (exact line not available)"

        vuln_blocks.append(
            f"--- Vulnerability {i} ---\n"
            f"Rule:     {rule_id}\n"
            f"Title:    {title}\n"
            f"Detail:   {info}\n"
            f"HOW TO FIX: {guidance}\n"
            f"Affected code:\n{location_block}"
        )

    context_block = ""
    if context_files:
        context_block = "\n\nRELATED FILES IN THE PROJECT (for context only — do not output these):\n"
        for fname, fcontent in context_files.items():
            context_block += f"\n// {fname}\n{fcontent[:600]}\n"

    return (
        "You are a senior Java security engineer performing a targeted security fix.\n\n"
        "OUTPUT RULES — follow exactly:\n"
        "1. Output ONLY the complete corrected Java source file as plain text.\n"
        "2. NO markdown, NO code fences (no ```), NO explanations before or after the code.\n"
        "3. Fix ONLY the vulnerabilities listed below. Do NOT rename, reformat, or refactor anything else.\n"
        "4. Do not Change the Business logic"
        "5. Preserve ALL business logic, method signatures, and class structure.\n"
        "6. The output must be a complete, compilable Java file — do not truncate.\n"
        "7. If a fix requires a new import, add it at the top. Add nothing else.\n"
        "8. Do NOT add TODO comments or placeholder comments as substitutes for real fixes.\n\n"
        f"VULNERABILITIES TO FIX:\n\n" + "\n\n".join(vuln_blocks) +
        context_block +
        f"\n\nSOURCE FILE TO FIX:\n\n{code}"
    )


# ---------------------------------------------------------------------------
# AI call with exponential backoff
# ---------------------------------------------------------------------------
def call_ai_fix(code, vulns, context_files=None):
    prompt = build_prompt(code, vulns, context_files)
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior Java security engineer. "
                    "Output ONLY the complete corrected Java source file as plain text. "
                    "No markdown, no code fences, no explanations, no TODO comments as fixes."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }

    url     = "https://models.github.ai/inference/chat/completions"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}", "Content-Type": "application/json"}

    for attempt in range(MAX_RETRIES):
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=90)
        if response.status_code == 429:
            wait = (2 ** attempt) + 1
            print(f"  ⚠ Rate limited. Retrying in {wait}s… (attempt {attempt+1}/{MAX_RETRIES})")
            time.sleep(wait)
            continue
        response.raise_for_status()
        return strip_markdown(response.json()["choices"][0]["message"]["content"])

    raise RuntimeError("Max retries exceeded.")


# ---------------------------------------------------------------------------
# Validate the fix
# ---------------------------------------------------------------------------
def validate_fix(original_code, fixed_code, vulns):
    if not fixed_code or not fixed_code.strip():
        return False, "AI returned empty response."

    if not re.search(r"\b(class|interface|enum)\b", fixed_code):
        return False, "No class/interface/enum found — response is likely truncated or wrong."

    orig_lines  = len(original_code.splitlines())
    fixed_lines = len(fixed_code.splitlines())
    if fixed_lines < orig_lines * 0.75:
        return False, f"Output is {fixed_lines} lines vs original {orig_lines} — likely truncated."

    if fixed_code.strip() == original_code.strip():
        return False, "AI returned identical code — vulnerability was not fixed."

    # Check that bad patterns were removed and good patterns were added
    warnings = []
    for vuln in vulns:
        _, entry = get_catalogue_entry(vuln)
        for pat in entry.get("bad_patterns", []):
            if re.search(pat, fixed_code):
                warnings.append(f"  ⚠ Bad pattern still present: {pat}")
        for pat in entry.get("good_patterns", []):
            if not re.search(pat, fixed_code):
                warnings.append(f"  ⚠ Expected fix pattern not found: {pat}")

    return True, "\n".join(warnings) if warnings else "OK"


# ---------------------------------------------------------------------------
# Generate companion files (e.g. SecurityConfig.java)
# ---------------------------------------------------------------------------
def generate_companion_files(file_path, vulns, src_root):
    """
    For vulns that require new files (e.g. SecurityConfig for CSRF),
    write the template into the same package directory as the affected file.
    """
    needed = set()
    for vuln in vulns:
        _, entry = get_catalogue_entry(vuln)
        for nf in entry.get("new_files", []):
            needed.add(nf)

    if not needed:
        return

    # Infer the Java package from the source file's package declaration
    package = "com.demo"
    try:
        with open(file_path, "r") as f:
            for line in f:
                m = re.match(r"^\s*package\s+([\w.]+)\s*;", line)
                if m:
                    package = m.group(1)
                    break
    except OSError:
        pass

    dest_dir = os.path.dirname(file_path)

    for fname in needed:
        dest_path = os.path.join(dest_dir, fname)
        if os.path.exists(dest_path):
            print(f"  ℹ {fname} already exists — skipping generation.")
            continue
        template = NEW_FILE_TEMPLATES.get(fname)
        if template:
            content = template.format(package=package)
            with open(dest_path, "w") as f:
                f.write(content)
            print(f"  ✓ Generated companion file: {dest_path}")
        else:
            print(f"  ⚠ No template available for {fname} — create it manually.")


# ---------------------------------------------------------------------------
# Load vulnerability report (supports both old Snyk format and new normalized format)
# ---------------------------------------------------------------------------
with open(SNYK_REPORT_FILE, "r") as f:
    report = json.load(f)

code_vulns  = report.get("code_vulnerabilities", [])
files_vulns = defaultdict(list)

# Detect format: normalized schema has 'scanner' field, old format does not
is_normalized = code_vulns and isinstance(code_vulns[0], dict) and "scanner" in code_vulns[0]

if is_normalized:
    # New normalized schema format
    # Extract file paths and vulnerability details from metadata
    for vuln in code_vulns:
        # For normalized findings, occurrences are stored in metadata
        occurrences = vuln.get("metadata", {}).get("occurrences", [])
        
        # If no occurrences in metadata, try to extract from other metadata fields
        if not occurrences:
            # Some scanners may store file path directly in metadata
            file_path = vuln.get("metadata", {}).get("file") or vuln.get("manifest_file")
            if file_path and os.path.isfile(file_path):
                # Create a synthetic occurrence from metadata
                occurrences = [{
                    "file": file_path,
                    "line_start": vuln.get("metadata", {}).get("line_start"),
                    "line_end": vuln.get("metadata", {}).get("line_end"),
                    "line": vuln.get("metadata", {}).get("line")
                }]
        
        # Group by file path
        for occ in occurrences:
            fp = occ.get("file")
            if fp and os.path.isfile(fp):
                # Convert normalized finding to format expected by fix logic
                v = {
                    "id": vuln.get("id"),
                    "rule_id": vuln.get("metadata", {}).get("rule_id") or vuln.get("id"),
                    "title": vuln.get("metadata", {}).get("title") or vuln.get("metadata", {}).get("rule_name") or "Code Vulnerability",
                    "info": vuln.get("metadata", {}).get("info") or vuln.get("metadata", {}).get("description") or "",
                    "type": vuln.get("metadata", {}).get("type") or vuln.get("metadata", {}).get("rule_id") or "",
                    "description": vuln.get("metadata", {}).get("description") or "",
                    "severity": vuln.get("severity", "medium"),
                    "cve": vuln.get("cve", []),
                    "scanner": vuln.get("scanner", "unknown"),
                    "occurrences": [occ],
                    "metadata": vuln.get("metadata", {})
                }
                files_vulns[fp].append(v)
else:
    # Old Snyk format (backward compatibility)
    for vuln in code_vulns:
        for occ in vuln.get("occurrences", []):
            fp = occ.get("file")
            if fp and os.path.isfile(fp):
                v = dict(vuln)
                v["occurrences"] = [occ]
                files_vulns[fp].append(v)

# ---------------------------------------------------------------------------
# Main processing loop
# ---------------------------------------------------------------------------
total   = len(files_vulns)
success = 0
failed  = 0

print(f"\nFound vulnerabilities in {total} file(s).\n")

# Build a small context map so the AI knows about related files
all_file_paths = list(files_vulns.keys())

for idx, (file_path, vulns_in_file) in enumerate(files_vulns.items(), 1):
    print(f"[{idx}/{total}] {file_path} — {len(vulns_in_file)} vulnerability(ies)")

    for v in vulns_in_file:
        rule  = v.get("rule_id") or v.get("id") or "?"
        title = v.get("title")   or v.get("type") or "?"
        info  = v.get("info")    or ""
        print(f"  • [{rule}] {title}")
        if info:
            print(f"    Snyk info: {info}")
        _, entry = get_catalogue_entry(v)
        print(f"    Fix strategy: {entry['guidance'][:120]}…")

    # Build context: other files in the same project that are being fixed
    context_files = {}
    for other_path in all_file_paths:
        if other_path != file_path:
            try:
                with open(other_path, "r") as f:
                    context_files[os.path.basename(other_path)] = f.read()
            except OSError:
                pass

    try:
        with open(file_path, "r") as f:
            original_code = f.read()

        fixed_code = call_ai_fix(original_code, vulns_in_file, context_files)

        is_valid, reason = validate_fix(original_code, fixed_code, vulns_in_file)
        if not is_valid:
            print(f"  ✗ Validation failed: {reason}")
            print(f"    File NOT modified.")
            failed += 1
            continue

        if reason != "OK":
            # Warnings (pattern checks) — still write the fix but flag it
            print(f"  ⚠ Fix written with warnings:\n{reason}")
        else:
            print(f"  ✓ All fix patterns verified.")


        with open(file_path, "w") as f:
            f.write(fixed_code)
        print(f"  ✓ File updated.")

        # Generate any required companion files (e.g. SecurityConfig.java for CSRF)
        generate_companion_files(file_path, vulns_in_file, BASE_DIR)

        success += 1

    except Exception as e:
        print(f"  ✗ Error: {e}")
        failed += 1

    time.sleep(1)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print(f"\n{'='*60}")
print(f"✅ Fixed:  {success} file(s)")
print(f"✗  Failed: {failed} file(s)")
print(f"{'='*60}")
print("Next steps:")
print("  2. If SecurityConfig.java was generated, set app.cors.allowed-origins")
print("     in src/main/resources/application.properties")
print("  3. Run: mvn clean compile")
print("  4. Re-run Snyk scan to verify issues are resolved.")