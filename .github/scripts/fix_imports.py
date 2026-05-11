import re
import sys
import os
import json
import time
import requests
from collections import defaultdict
from defusedxml.ElementTree import parse
from xml.etree.ElementTree import register_namespace
from xml.etree.ElementTree import SubElement

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN environment variable not set")

BASE_DIR = os.getcwd()

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)

BUILD_LOG_FILE = safe_path(sys.argv[1])
POM_FILE = safe_path(sys.argv[2])
SRC_DIR = safe_path(sys.argv[3])

# ---------------------------------------------------------------------------
# Rate limiting config
# ---------------------------------------------------------------------------
BATCH_SIZE = 20          # Number of symbols to resolve per API call
INTER_BATCH_DELAY = 2.0  # Seconds to wait between batch calls
MAX_RETRIES = 5          # Max retry attempts on rate limit (429)

# ---------------------------------------------------------------------------
# Known mechanical renames
# ---------------------------------------------------------------------------
KNOWN_RENAMES = [
    ("import javax.persistence.", "import jakarta.persistence."),
    ("import javax.validation.", "import jakarta.validation."),
    ("import javax.transaction.", "import jakarta.transaction."),
    ("import javax.servlet.", "import jakarta.servlet."),
    ("import javax.annotation.", "import jakarta.annotation."),
    ("import org.junit.Test", "import org.junit.jupiter.api.Test"),
    ("import org.junit.Before", "import org.junit.jupiter.api.BeforeEach"),
    ("import org.junit.After", "import org.junit.jupiter.api.AfterEach"),
    ("import org.junit.Assert", "import org.junit.jupiter.api.Assertions"),
    ("import org.junit.Ignore", "import org.junit.jupiter.api.Disabled"),
    ("import org.junit.runner.RunWith", "import org.junit.jupiter.api.extension.ExtendWith"),
]

# ---------------------------------------------------------------------------
# Retry with exponential backoff
# ---------------------------------------------------------------------------
def call_with_retry(fn, *args, **kwargs):
    """
    Calls fn(*args, **kwargs) and retries up to MAX_RETRIES times on HTTP 429.
    Waits 2^attempt + 1 seconds between retries (2, 3, 5, 9, 17 seconds).
    Raises on non-429 HTTP errors or if all retries are exhausted.
    """
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
        except requests.exceptions.ConnectionError as e:
            wait = (2 ** attempt) + 1
            print(f"  ⚠ Connection error: {e}. Retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.Timeout as e:
            wait = (2 ** attempt) + 1
            print(f"  ⚠ Request timed out. Retrying in {wait}s...")
            time.sleep(wait)
    raise RuntimeError(f"API call failed after {MAX_RETRIES} retries.")


# ---------------------------------------------------------------------------
# Parse Maven compile errors
# ---------------------------------------------------------------------------
def parse_compile_errors(log_file):
    errors = defaultdict(list)
    code_issues = defaultdict(list)
    missing_deps = set()

    pattern = re.compile(
        r"(?:\[ERROR\]|Error:)\s+([\w/.\-]+\.java):\[(\d+),(\d+)\]\s+(.+)"
    )
    dep_pattern = re.compile(
        r"(?:\[ERROR\]|Error:)\s+Could not find artifact ([\w\.\-:]+)"
    )
    missing_package_pattern = re.compile(
        r"package\s+([\w\.]+)\s+does not exist"
    )
    # Matches all three symbol kinds javac reports on follow-up lines:
    #   symbol:   class  Foo
    #   symbol:   variable  Foo
    #   symbol:   method  foo(...)
    missing_symbol_pattern = re.compile(
        r"symbol:\s+(?:class|variable|method)\s+(\w+)"
    )

    last_error = None

    def is_code_issue(message):
        # Delegate to the module-level classify_error so there is a single
        # source of truth for what counts as a structural code problem.
        return classify_error(message) == "code_fix"

    with open(log_file, "r") as f:
        for raw_line in f:
            line = raw_line.strip()

            # ---------------------------------------------------
            # Main compile error
            # ---------------------------------------------------
            m = pattern.match(line)
            if m:
                print(f"Parsed error: {line}")

                file_path = m.group(1)
                lineno = int(m.group(2))
                col = int(m.group(3))
                message = m.group(4).strip()

                error_entry = {
                    "line": lineno,
                    "col": col,
                    "message": message
                }

                errors[file_path].append(error_entry)
                last_error = error_entry

                # -------------------------------
                # Detect missing package (dependency)
                # -------------------------------
                pkg_match = missing_package_pattern.search(message)
                if pkg_match:
                    missing_deps.add(pkg_match.group(1))

                # -------------------------------
                # Detect CODE issues
                # -------------------------------
                if is_code_issue(message):
                    code_issues[file_path].append(error_entry)

                continue

            # ---------------------------------------------------
            # Missing dependency
            # ---------------------------------------------------
            dep_m = dep_pattern.search(line)
            if dep_m:
                missing_deps.add(dep_m.group(1))
                continue

            # ---------------------------------------------------
            # Follow-up lines (symbol, package)
            # ---------------------------------------------------
            if last_error:
                symbol_match = missing_symbol_pattern.search(line)
                if symbol_match:
                    # Use a list so multiple symbol follow-up lines for
                    # errors at the same line number do not overwrite each
                    # other. Captures class, variable, and method symbols.
                    last_error.setdefault("missing_classes", []).append(
                        symbol_match.group(1)
                    )

                pkg_match = missing_package_pattern.search(line)
                if pkg_match:
                    missing_deps.add(pkg_match.group(1))

    return errors, missing_deps, code_issues


# ---------------------------------------------------------------------------
# Classify error — single source of truth for all three fix strategies.
#
# Returns one of:
#   "symbol_or_import"  → Step 2: resolve & inject missing import
#   "pom_dependency"    → Step 3: add missing artifact to pom.xml
#   "code_fix"          → Step 4: ai_fix_code rewrites the source file
#   "ignored"           → informational / not actionable
# ---------------------------------------------------------------------------
def classify_error(message):
    msg = message.lower()

    # ------------------------------------------------------------------ #
    # Step 2 — missing symbol / import                                    #
    # ------------------------------------------------------------------ #
    if any(p in msg for p in (
        "cannot find symbol",
        "package does not exist",
        "cannot be resolved to a type",
    )):
        return "symbol_or_import"

    # ------------------------------------------------------------------ #
    # Step 3 — missing Maven artifact                                     #
    # ------------------------------------------------------------------ #
    if "could not find artifact" in msg:
        return "pom_dependency"

    # ------------------------------------------------------------------ #
    # Step 4 — structural / logic errors that require AI code rewrite     #
    # ------------------------------------------------------------------ #
    if any(p in msg for p in (
        # Type & signature mismatches
        "incompatible types",
        "cannot be applied to given types",
        "actual and formal argument lists differ",
        "bad return type",
        "cannot infer type arguments",
        "inconvertible types",
        "possible loss of precision",
        # Override / abstract / visibility
        "does not override",
        "method does not override",
        "is abstract; cannot be instantiated",
        "has private access",
        "is not public",
        "cannot access",
        # Lambda / functional
        "lambda expression",
        # Exception-handling issues
        "is never thrown in body of corresponding try statement",
        "unreported exception",
        "exception never thrown",
        # Control-flow / structure
        "unreachable statement",
        "missing return statement",
        # Duplicate definitions
        "is already defined",
        "duplicate class",
        # Method resolution (type is known but method is wrong)
        "method does not exist",
        "cannot find method",
    )):
        return "code_fix"

    # ------------------------------------------------------------------ #
    # Informational lines — not directly fixable                          #
    # ------------------------------------------------------------------ #
    return "ignored"


def clean_dependency_xml(text):
    """Strip markdown fences and any <dependencies> wrapper the AI may have added.
    Always returns one or more bare <dependency>...</dependency> blocks."""
    # Remove markdown code fences
    text = re.sub(r"```xml", "", text)
    text = re.sub(r"```", "", text)
    text = text.strip()

    # If the AI wrapped the snippet in <dependencies>...</dependencies>, unwrap it
    # so inject_dependency only ever receives bare <dependency> blocks.
    wrapper_match = re.search(
        r"<dependencies[^>]*>(.*?)</dependencies>",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if wrapper_match:
        text = wrapper_match.group(1).strip()

    return text


# ---------------------------------------------------------------------------
# Apply known mechanical renames to code
# ---------------------------------------------------------------------------
def apply_known_renames(code):
    changes = []
    for old, new in KNOWN_RENAMES:
        if old in code:
            code = code.replace(old, new)
            changes.append(f"Replaced: {old!r} → {new!r}")
    return code, changes


# ---------------------------------------------------------------------------
# Extract unknown symbols
# ---------------------------------------------------------------------------
def extract_unknown_symbols(errors_by_file):
    symbol_to_files = defaultdict(list)
    for file_path, errs in errors_by_file.items():
        for err in errs:
            error_type = classify_error(err["message"])
            if error_type == "symbol_or_import":
                # Primary: symbol detail lines were parsed into missing_classes
                # list by the log parser (handles "Error:" style logs where the
                # "symbol: class X" line appears separately after the main error).
                symbols_found = err.get("missing_classes", [])

                # Fallback: some log formats embed the symbol inline in the
                # message itself, e.g. "[ERROR] ... cannot find symbol: class Foo"
                if not symbols_found:
                    match = re.search(
                        r"symbol:\s+(?:class|variable|method)\s+(\S+)",
                        err["message"]
                    )
                    if match:
                        symbols_found = [match.group(1)]

                for sym in symbols_found:
                    if file_path not in symbol_to_files[sym]:
                        symbol_to_files[sym].append(file_path)

            # "code_fix" and "ignored" errors are not symbol/import issues;
            # code_fix errors are handled entirely by Step 4 via code_issues.
    return symbol_to_files


# ---------------------------------------------------------------------------
# Raw API call (wrapped by call_with_retry)
# ---------------------------------------------------------------------------
def _post_to_api(payload):
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


# ---------------------------------------------------------------------------
# AI suggest imports — BATCHED (up to BATCH_SIZE symbols per call)
# ---------------------------------------------------------------------------
def ai_suggest_imports_batch(symbol_snippet_pairs):
    """
    symbol_snippet_pairs: list of (symbol_name, code_snippet)
    Returns: dict mapping symbol_name -> import statement or "UNKNOWN"
    """
    items_text = "\n\n".join(
        f"{i + 1}. Symbol: {sym}\nSnippet:\n{snip[:400]}"
        for i, (sym, snip) in enumerate(symbol_snippet_pairs)
    )

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a Java migration expert. "
                    "Given a numbered list of unresolved Java symbols and their code snippets, "
                    "respond ONLY with a valid JSON array of import statements in the SAME ORDER. "
                    "Use 'UNKNOWN' for any symbol you cannot resolve. "
                    "Example: [\"import org.springframework.foo.Bar;\", \"UNKNOWN\"]. "
                    "No markdown, no explanations, no extra text — only the JSON array."
                ),
            },
            {"role": "user", "content": items_text},
        ],
    }

    result = call_with_retry(_post_to_api, payload)
    raw = result["choices"][0]["message"]["content"].strip()

    # Strip markdown fences if model misbehaves
    raw = re.sub(r"```json|```", "", raw).strip()

    try:
        suggestions = json.loads(raw)
    except json.JSONDecodeError:
        print(f"  ⚠ Could not parse batch response as JSON. Raw:\n{raw[:300]}")
        suggestions = ["UNKNOWN"] * len(symbol_snippet_pairs)

    # Pad if model returned fewer items than expected
    while len(suggestions) < len(symbol_snippet_pairs):
        suggestions.append("UNKNOWN")

    return {sym: suggestions[i] for i, (sym, _) in enumerate(symbol_snippet_pairs)}


# ---------------------------------------------------------------------------
# AI suggest pom fix — with retry (dependencies kept one-by-one, usually few)
# ---------------------------------------------------------------------------
def ai_suggest_pom_dependency(missing_dep, pom_content):
    print(f"  → AI resolving missing dependency: {missing_dep}")

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": (
                     "You are a Maven expert.\n"
                     "Return ONLY a valid Maven <dependency> XML snippet.\n"
                        "CRITICAL RULES:\n"
                        "- Use ONLY REAL versions that exist in Maven Central.\n"
                        "- Return a widely used stable version for this dependency.\n"
                        "- Do NOT return UNKNOWN.\n"
                        "- Avoid guessing unusual patch numbers.\n"
                        "- Ensure version format matches real releases (no invented patch numbers).\n"
                        "- For Spring dependencies, prefer using latest known stable versions.\n"
                        "- For Jackson, use consistent versions across modules.\n"
                        "Output raw XML only. No explanation."
                    ),
            },
            {
                "role": "user",
                "content": f"Missing artifact: {missing_dep}\nCurrent pom.xml:\n{pom_content[:1000]}",
            },
        ],
    }

    result = call_with_retry(_post_to_api, payload)
    return result["choices"][0]["message"]["content"].strip()

def ai_fix_code(file_path, code, errors):
    error_text = "\n".join(
        f"Line {e['line']}: {e['message']}" for e in errors
    )

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior Java developer fixing compilation errors.\n"
                    "Return ONLY the FULL corrected Java file.\n"
                    "Do NOT add explanations or markdown.\n"
                    "Preserve existing logic unless necessary.\n"
                ),
            },
            {
                "role": "user",
                "content": f"Errors:\n{error_text}\n\nCode:\n{code[:4000]}",
            },
        ],
    }

    try:
        result = call_with_retry(_post_to_api, payload)
        fixed_code = result["choices"][0]["message"]["content"]

        # Cleanup
        fixed_code = re.sub(r"```java|```", "", fixed_code).strip()

        # Basic validation
        if "class " in fixed_code:
            return fixed_code

    except Exception as e:
        print(f"  ✗ AI fix failed for {file_path}: {e}")

    return None

# ---------------------------------------------------------------------------
# Inject import into Java file
# ---------------------------------------------------------------------------
def inject_import(code, import_statement):
    if import_statement in code:
        return code
    lines = code.splitlines(keepends=True)
    last_import_idx = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("import "):
            last_import_idx = i
    if last_import_idx == -1:
        for i, line in enumerate(lines):
            if line.strip().startswith("package "):
                lines.insert(i + 1, "\n" + import_statement + "\n")
                return "".join(lines)
        return import_statement + "\n" + code
    lines.insert(last_import_idx + 1, import_statement + "\n")
    return "".join(lines)


# ---------------------------------------------------------------------------
# Insert dependency into pom.xml
# ---------------------------------------------------------------------------
def inject_dependency(pom_content, dependency_xml):
    """Safely insert a <dependency> block into pom_content.

    Handles four failure modes of the naive string-replace approach:
      1. AI returns a <dependencies>-wrapped block  → unwrapped by clean_dependency_xml
      2. Duplicate injection                         → groupId+artifactId dedup check
      3. Multiple </dependencies> in the file       → only the LAST one is the target
         (pluginManagement / profiles also have <dependencies>)
      4. </dependencies> inside XML comments        → we insert before the final real tag
    """
    dependency_xml = clean_dependency_xml(dependency_xml)

    # Extract groupId + artifactId for a content-aware duplicate check
    # (avoids false misses when whitespace differs between the stored and
    # incoming snippets).
    gid_match = re.search(r"<groupId>\s*(.*?)\s*</groupId>", dependency_xml)
    aid_match = re.search(r"<artifactId>\s*(.*?)\s*</artifactId>", dependency_xml)
    if gid_match and aid_match:
        gid, aid = gid_match.group(1), aid_match.group(1)
        if gid in pom_content and aid in pom_content:
            print(f"  ⚠ Dependency {gid}:{aid} already present in POM — skipping.")
            return pom_content

    # Find the position of the LAST </dependencies> closing tag so we insert
    # into the main <dependencies> block, not one nested inside pluginManagement.
    last_close = pom_content.rfind("</dependencies>")
    if last_close != -1:
        pom_content = (
            pom_content[:last_close]
            + dependency_xml + ""
            + pom_content[last_close:]
        )
    else:
        pom_content += "<dependencies>" + dependency_xml + "</dependencies>"

    return pom_content


# ------------------------ Java Version Guardrail ------------------------
def upgrade_java_version_for_spring(pom_file):
    ns = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
    register_namespace('', ns['mvn'])
    tree = parse(pom_file)
    root = tree.getroot()
    properties = root.find('mvn:properties', ns)
    spring_version = None
    if properties is not None:
        spring_elem = properties.find('mvn:spring.version', ns)
        if spring_elem is not None:
            spring_version = spring_elem.text.strip()
    required_java = "1.8"
    if spring_version and int(spring_version.split(".")[0]) >= 6:
        required_java = "17"
    if properties is None:
        properties = SubElemet(root, 'properties')
    java_elem = properties.find('mvn:java.version', ns)
    if java_elem is None:
        java_elem = SubElemet(properties, 'java.version')
    current_version = java_elem.text.strip() if java_elem.text else "1.8"
    if current_version < required_java:
        java_elem.text = required_java
        print(f"  ✓ Updated <java.version> from {current_version} → {required_java}")
    else:
        print(f"  ✓ <java.version> already {current_version}, no change")
    tree.write(pom_file, encoding="utf-8", xml_declaration=True)

# ---------------------------------------------------------------------------
# Resolve the on-disk path for a file path as it appears in the build log.
# Build logs often contain paths relative to the project root or Maven
# module root, not necessarily matching os.getcwd() directly.
# ---------------------------------------------------------------------------
def resolve_source_file(file_path):
    """
    Try several strategies to locate a source file referenced in the build log.
    Returns the resolved absolute path, or None if the file cannot be found.
    """
    # Strategy 1: treat as-is (already absolute, or relative to cwd)
    candidate = file_path if os.path.isabs(file_path) else os.path.join(BASE_DIR, file_path)
    candidate = os.path.realpath(candidate)
    if os.path.isfile(candidate):
        return candidate

    # Strategy 2: search under SRC_DIR by basename
    fname = os.path.basename(file_path)
    for root, _, files in os.walk(SRC_DIR):
        if fname in files:
            return os.path.realpath(os.path.join(root, fname))

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print(f"Parsing build log: {BUILD_LOG_FILE}")
    errors_by_file, missing_deps, code_issues  = parse_compile_errors(BUILD_LOG_FILE)

    print(f"Found errors in {len(errors_by_file)} file(s).")
    print(f"Found {len(missing_deps)} missing dependency(ies).")
    print(f"Found {len(code_issues)} code issue(es).")
    print(f"Error file:s {list(errors_by_file.keys())}")
    print(f"Depe file:s {list(missing_deps)}")
    print(f"code isses file:s {list(code_issues.keys())}")

    # ------------------------------------------------------------------
    # Step 1: Apply known mechanical renames (no API calls)
    # ------------------------------------------------------------------
    print("\n[Step 1] Applying mechanical renames...")
    for root, _, files in os.walk(SRC_DIR):
        for fname in files:
            if fname.endswith(".java"):
                path = os.path.join(root, fname)
                with open(path, "r") as f:
                    code = f.read()
                new_code, changes = apply_known_renames(code)
                if changes:
                    with open(path, "w") as f:
                        f.write(new_code)
                    for c in changes:
                        print(f"  [{path}] {c}")#

    upgrade_java_version_for_spring(POM_FILE)

    # ------------------------------------------------------------------
    # Step 2: Resolve unknown symbols via AI — batched with caching
    # ------------------------------------------------------------------
    print("\n[Step 2] Resolving unknown symbols via AI (batched)...")
    unknown_symbols = extract_unknown_symbols(errors_by_file)
    symbol_items = list(unknown_symbols.items())  # [(symbol, [files...]), ...]
    print("unkonw symbol :", symbol_items)

    import_cache = {}  # symbol -> resolved import statement

    # Build (symbol, snippet) pairs for all uncached symbols
    pairs_to_resolve = []
    for symbol, files_list in symbol_items:
        if symbol not in import_cache:
            sample_file = files_list[0]
            try:
                with open(sample_file, "r") as f:
                    snippet = f.read()
            except OSError as e:
                print(f"  ⚠ Could not read {sample_file}: {e}")
                snippet = ""
            pairs_to_resolve.append((symbol, snippet))

    print(f"  Total unique symbols to resolve: {len(pairs_to_resolve)}")

    # Process in batches
    for batch_start in range(0, len(pairs_to_resolve), BATCH_SIZE):
        batch = pairs_to_resolve[batch_start: batch_start + BATCH_SIZE]
        batch_num = (batch_start // BATCH_SIZE) + 1
        total_batches = (len(pairs_to_resolve) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"  → Batch {batch_num}/{total_batches}: resolving {len(batch)} symbol(s)...")

        try:
            results = ai_suggest_imports_batch(batch)
            import_cache.update(results)
        except Exception as e:
            print(f"  ✗ Batch {batch_num} failed: {e}. Symbols in this batch will be skipped.")
            for sym, _ in batch:
                import_cache[sym] = "UNKNOWN"

        # Delay between batches to respect rate limits
        if batch_start + BATCH_SIZE < len(pairs_to_resolve):
            time.sleep(INTER_BATCH_DELAY)

    # Apply resolved imports to files
    for symbol, files_list in symbol_items:
        suggestion = import_cache.get(symbol, "UNKNOWN")
        if suggestion == "UNKNOWN" or not suggestion.startswith("import "):
            print(f"  ✗ Could not resolve import for: {symbol}")
            continue
        for fpath in files_list:
            try:
                with open(fpath, "r") as f:
                    code = f.read()
                updated = inject_import(code, suggestion)
                if updated != code:
                    with open(fpath, "w") as f:
                        f.write(updated)
                    print(f"  ✓ Injected [{suggestion}] into {fpath}")
            except OSError as e:
                print(f"  ✗ Could not update {fpath}: {e}")

    # ------------------------------------------------------------------
    # Step 3: Resolve missing dependencies via AI — with retry + delay
    # ------------------------------------------------------------------
    print("\n[Step 3] Resolving missing dependencies in POM via AI...")
    try:
        with open(POM_FILE, "r") as f:
            pom_content = f.read()
    except OSError as e:
        print(f"  ✗ Could not read POM file: {e}")
        return

    for i, dep in enumerate(missing_deps):
        try:
            suggestion = ai_suggest_pom_dependency(dep, pom_content)
            if suggestion != "UNKNOWN":
                pom_content = inject_dependency(pom_content, suggestion)
                print(f"  ✓ Added dependency for: {dep}")
            else:
                print(f"  ✗ Could not resolve dependency for: {dep}")
        except Exception as e:
            print(f"  ✗ Failed to resolve dependency for {dep}: {e}")

        # Small delay between individual POM dependency calls
        if i < len(missing_deps) - 1:
            time.sleep(1.0)

    try:
        with open(POM_FILE, "w") as f:
            f.write(pom_content)
    except OSError as e:
        print(f"  ✗ Could not write POM file: {e}")
        return

    # ------------------------------------------------------------------
    # Step 4: AI-fix files with structural/logic compile errors.
    # code_issues is already pre-filtered by parse_compile_errors to only
    # contain errors that import injection and POM fixes cannot address
    # (incompatible types, bad return type, lambda issues, etc.).
    # No extra filtering needed here.
    # ------------------------------------------------------------------
    print("\n[Step 4] AI-fixing source files with structural/logic compile errors...")

    if not code_issues:
        print("  ✓ No structural code errors found — no AI code fix needed.")
    else:
        print(f"  Found {len(code_issues)} file(s) with errors requiring AI code fix.")
        for fp, errs in code_issues.items():
            for e in errs:
                print(f"    {fp}  line {e['line']}: {e['message']}")

    files_to_fix = code_issues

    base_real = os.path.realpath(BASE_DIR)

    for i, (file_path, errs) in enumerate(files_to_fix.items()):
        resolved = resolve_source_file(file_path)

        if resolved is None:
            print(f"  ✗ Skipping {file_path}: file not found on disk.")
            continue

        # Safety: reject any path that escaped the project root.
        if not resolved.startswith(base_real):
            print(f"  ✗ Skipping {file_path}: resolved path outside project directory.")
            continue

        try:
            with open(resolved, "r") as f:
                original_code = f.read()
        except OSError as e:
            print(f"  ✗ Could not read {resolved}: {e}")
            continue

        print(f"\n  → AI fixing {resolved} ({len(errs)} structural error(s)):")
        for e in errs:
            print(f"      Line {e['line']}: {e['message']}")

        fixed_code = ai_fix_code(resolved, original_code, errs)

        if fixed_code:
            try:
                with open(resolved, "w") as f:
                    f.write(fixed_code)
                print(f"  ✓ Fixed  {resolved}")
            except OSError as e:
                print(f"  ✗ Could not write fixed file {resolved}: {e}")
        else:
            print(f"  ✗ AI could not produce a valid fix for {resolved}.")

        # Throttle between per-file AI calls to avoid rate limiting.
        if i < len(files_to_fix) - 1:
            time.sleep(INTER_BATCH_DELAY)

    print("\n✅ fix_build.py complete. Run 'mvn clean compile' to verify build.")


if __name__ == "__main__":
    main()