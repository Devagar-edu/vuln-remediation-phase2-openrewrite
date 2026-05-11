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
    python fix_build_errors.py build1.log
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

BASE_DIR = os.getcwd()

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)

BUILD_LOG = safe_path(sys.argv[1])


AI_ENDPOINT  = "https://models.github.ai/inference/chat/completions"
AI_MODEL     = "gpt-4o-mini"


# ─────────────────────────────────────────────────────────────────────────────
# Parse build log → { file_path: [ "Line N: error message", ... ] }
# ─────────────────────────────────────────────────────────────────────────────
def parse_errors(log_file):
    errors_by_file = defaultdict(list)
    pattern = re.compile(r"\[ERROR\]\s+([\w/.\-]+\.java):\[(\d+),\d+\]\s+(.+)")
    with open(log_file) as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                errors_by_file[m.group(1)].append(
                    f"Line {m.group(2)}: {m.group(3).strip()}"
                )
    return errors_by_file


# ─────────────────────────────────────────────────────────────────────────────
# AI call — one call per file, all errors for that file sent together.
# System prompt is strictly scoped: fix only what is broken, nothing more.
# ─────────────────────────────────────────────────────────────────────────────
def ai_fix_file(file_path, code, error_lines):
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
                "content": (
                    "This Java file has compile errors introduced by a dependency "
                    "version upgrade in pom.xml. Fix ONLY those errors.\n\n"
                    "RULES:\n"
                    "1. Fix every compile error listed.\n"
                    "2. Do NOT change any business logic.\n"
                    "3. Do NOT add, remove, or rename methods, fields, or classes.\n"
                    "4. Do NOT refactor, modernise, or improve anything.\n"
                    "5. Do NOT change any line that is not causing a compile error.\n"
                    "6. The output must compile successfully with the upgraded dependencies.\n\n"
                    f"COMPILE ERRORS:\n{chr(10).join(error_lines)}\n\n"
                    f"FILE: {file_path}\n"
                    f"CONTENT:\n{code}"
                )
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
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(f"Parsing: {BUILD_LOG}")
    errors_by_file = parse_errors(BUILD_LOG)

    if not errors_by_file:
        print("No Java compile errors found — nothing to fix.")
        return

    total_files  = len(errors_by_file)
    total_errors = sum(len(v) for v in errors_by_file.values())
    print(f"Found {total_errors} error(s) across {total_files} file(s)\n")

    stats  = {"fixed": 0, "skipped": 0, "errors": 0}
    report = []

    for file_path, error_lines in errors_by_file.items():
        print(f"{'─'*60}")
        print(f"File: {file_path}  ({len(error_lines)} error(s))")
        for e in error_lines:
            print(f"  {e}")

        if not os.path.isfile(file_path):
            print(f"  SKIP — not found on disk")
            stats["skipped"] += 1
            report.append(f"SKIPPED_MISSING: {file_path}")
            continue

        with open(file_path) as f:
            original = f.read()

        try:
            fixed = ai_fix_file(file_path, original, error_lines)

            # Strip accidental markdown fences
            if fixed.startswith("```"):
                fixed = re.sub(r"^```\w*\n?", "", fixed)
                fixed = re.sub(r"\n?```$",     "", fixed).strip()

            if fixed and fixed != original:
                with open(file_path, "w") as f:
                    f.write(fixed)
                print(f"  ✅ Fixed")
                stats["fixed"] += 1
                report.append(f"FIXED: {file_path} ({len(error_lines)} errors)")
            else:
                print(f"  ℹ️  No change returned by AI")
                stats["skipped"] += 1
                report.append(f"UNCHANGED: {file_path}")

        except Exception as e:
            print(f"  ❌ {e}")
            stats["errors"] += 1
            report.append(f"ERROR: {file_path} — {e}")

    with open("fix_build_errors_report.txt", "w") as f:
        f.write(f"Files: {total_files} | Fixed: {stats['fixed']} | "
                f"Skipped: {stats['skipped']} | Errors: {stats['errors']}\n\n")
        f.write("\n".join(report))

    print(f"\n{'═'*60}")
    print(f"Done. Fixed: {stats['fixed']} | Skipped: {stats['skipped']} | Errors: {stats['errors']}")


if __name__ == "__main__":
    main()