"""
fix_build_errors.py

Reads a Maven build log and fixes compile errors caused by dependency
version upgrades in pom.xml.

PURPOSE: This script exists ONLY to restore compile success after
pom.xml dependency changes. It does NOT perform Java version migrations,
modernise code, or change anything the compiler is not complaining about.
If the original code compiled fine before the dep upgrade, only the
minimum change needed to compile again is made.

Design:
  - Groups all errors by file — one AI call per file with ALL its errors
  - AI receives only: the file content + the exact compiler error lines
  - No migration hints or upgrade goals are passed to the AI
  - Writes fix_build_errors_report.txt summarising results

Usage:
    python fix_build_errors.py build.log pom.xml src/
"""

import json
import os
import re
import sys
import requests
from collections import defaultdict

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN environment variable not set")

AI_ENDPOINT  = "https://models.github.ai/inference/chat/completions"
AI_MODEL     = "gpt-4o-mini"


# ─────────────────────────────────────────────────────────────────────────────
# Parse build log → list of error dictionaries
# ─────────────────────────────────────────────────────────────────────────────
def parse_compilation_errors(build_log):
    """
    Extract error messages from Maven build log.
    
    Args:
        build_log (str): Path to build log file
        
    Returns:
        list: List of error dictionaries with keys: file, line, message
    """
    errors = []
    pattern = re.compile(r"\[ERROR\]\s+([\w/.\-]+\.java):\[(\d+),\d+\]\s+(.+)")
    with open(build_log) as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                errors.append({
                    'file': m.group(1),
                    'line': m.group(2),
                    'message': m.group(3).strip()
                })
    return errors


# ─────────────────────────────────────────────────────────────────────────────
# Group errors by file path
# ─────────────────────────────────────────────────────────────────────────────
def group_by_file(errors):
    """
    Organize errors by file path.
    
    Args:
        errors (list): List of error dictionaries from parse_compilation_errors
        
    Returns:
        dict: Dictionary mapping file paths to lists of error strings
    """
    errors_by_file = defaultdict(list)
    for error in errors:
        error_str = f"Line {error['line']}: {error['message']}"
        errors_by_file[error['file']].append(error_str)
    return dict(errors_by_file)


# ─────────────────────────────────────────────────────────────────────────────
# Format errors for AI prompt
# ─────────────────────────────────────────────────────────────────────────────
def format_errors(file_errors):
    """
    Format errors for AI prompt.
    
    Args:
        file_errors (list): List of error strings for a single file
        
    Returns:
        str: Formatted error string for AI prompt
    """
    return "\n".join(file_errors)


# ─────────────────────────────────────────────────────────────────────────────
# Call GitHub Models API to generate fix
# ─────────────────────────────────────────────────────────────────────────────
def call_github_models_api(prompt):
    """
    Call AI for fix generation.
    
    Args:
        prompt (str): The complete prompt for the AI
        
    Returns:
        str: The AI-generated fixed code
    """
    payload = {
        "model": AI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a Java compiler error fixer. "
                    "Your only job is to make the Java file compile by resolving "
                    "the exact errors listed — nothing more. "
                    "Output ONLY the complete fixed Java source code. "
                    "No markdown, no code fences, no explanations."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    resp = requests.post(
        AI_ENDPOINT,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Content-Type":  "application/json"
        },
        data=json.dumps(payload),
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


# ─────────────────────────────────────────────────────────────────────────────
# Generate report summarizing fixes
# ─────────────────────────────────────────────────────────────────────────────
def generate_report(filename, fixes_applied):
    """
    Generate report file summarizing fixes applied.
    
    Args:
        filename (str): Path to report file to generate
        fixes_applied (list): List of fix result dictionaries
    """
    total_files = len([f for f in fixes_applied if f['status'] == 'FIXED'])
    skipped = len([f for f in fixes_applied if f['status'] in ['SKIPPED_MISSING', 'UNCHANGED']])
    errors = len([f for f in fixes_applied if f['status'] == 'ERROR'])
    
    with open(filename, "w") as f:
        f.write(f"Files: {len(fixes_applied)} | Fixed: {total_files} | "
                f"Skipped: {skipped} | Errors: {errors}\n\n")
        for fix in fixes_applied:
            f.write(f"{fix['status']}: {fix['file']}")
            if 'error_count' in fix:
                f.write(f" ({fix['error_count']} errors)")
            if 'error_message' in fix:
                f.write(f" — {fix['error_message']}")
            f.write("\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main function - fix build errors
# ─────────────────────────────────────────────────────────────────────────────
def fix_build_errors(build_log, pom_file, src_dir):
    """
    Main function to fix build errors.
    
    Args:
        build_log (str): Path to compilation log
        pom_file (str): Path to pom.xml (for context, not currently used)
        src_dir (str): Path to source directory (for context, not currently used)
        
    Returns:
        list: List of fix result dictionaries
    """
    print(f"Parsing: {build_log}")
    errors = parse_compilation_errors(build_log)
    errors_by_file = group_by_file(errors)

    if not errors_by_file:
        print("No Java compile errors found — nothing to fix.")
        return []

    total_files  = len(errors_by_file)
    total_errors = sum(len(v) for v in errors_by_file.values())
    print(f"Found {total_errors} error(s) across {total_files} file(s)\n")

    fixes_applied = []

    for file_path, error_lines in errors_by_file.items():
        print(f"{'─'*60}")
        print(f"File: {file_path}  ({len(error_lines)} error(s))")
        for e in error_lines:
            print(f"  {e}")

        if not os.path.isfile(file_path):
            print(f"  SKIP — not found on disk")
            fixes_applied.append({
                'status': 'SKIPPED_MISSING',
                'file': file_path,
                'error_count': len(error_lines)
            })
            continue

        with open(file_path) as f:
            original = f.read()

        try:
            # Prepare AI prompt
            formatted_errors = format_errors(error_lines)
            prompt = (
                "This Java file has compile errors introduced by a dependency "
                "version upgrade in pom.xml. Fix ONLY those errors.\n\n"
                "RULES:\n"
                "1. Fix every compile error listed.\n"
                "2. Do NOT change any business logic.\n"
                "3. Do NOT add, remove, or rename methods, fields, or classes.\n"
                "4. Do NOT refactor, modernise, or improve anything.\n"
                "5. Do NOT change any line that is not causing a compile error.\n"
                "6. The output must compile successfully with the upgraded dependencies.\n\n"
                f"COMPILE ERRORS:\n{formatted_errors}\n\n"
                f"FILE: {file_path}\n"
                f"CONTENT:\n{original}"
            )
            
            # Call AI to generate fix
            fixed = call_github_models_api(prompt)

            # Strip accidental markdown fences
            if fixed.startswith("```"):
                fixed = re.sub(r"^```\w*\n?", "", fixed)
                fixed = re.sub(r"\n?```$",     "", fixed).strip()

            if fixed and fixed != original:
                with open(file_path, "w") as f:
                    f.write(fixed)
                print(f"  ✅ Fixed")
                fixes_applied.append({
                    'status': 'FIXED',
                    'file': file_path,
                    'error_count': len(error_lines)
                })
            else:
                print(f"  ℹ️  No change returned by AI")
                fixes_applied.append({
                    'status': 'UNCHANGED',
                    'file': file_path,
                    'error_count': len(error_lines)
                })

        except Exception as e:
            print(f"  ❌ {e}")
            fixes_applied.append({
                'status': 'ERROR',
                'file': file_path,
                'error_count': len(error_lines),
                'error_message': str(e)
            })

    # Generate report
    generate_report("fix_build_errors_report.txt", fixes_applied)

    fixed_count = len([f for f in fixes_applied if f['status'] == 'FIXED'])
    skipped_count = len([f for f in fixes_applied if f['status'] in ['SKIPPED_MISSING', 'UNCHANGED']])
    error_count = len([f for f in fixes_applied if f['status'] == 'ERROR'])

    print(f"\n{'═'*60}")
    print(f"Done. Fixed: {fixed_count} | Skipped: {skipped_count} | Errors: {error_count}")
    
    return fixes_applied


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python fix_build_errors.py <build_log> <pom_file> <src_dir>")
        print("Example: python fix_build_errors.py build.log pom.xml src/")
        sys.exit(1)
    
    build_log = sys.argv[1]
    pom_file = sys.argv[2]
    src_dir = sys.argv[3]
    
    fix_build_errors(build_log, pom_file, src_dir)