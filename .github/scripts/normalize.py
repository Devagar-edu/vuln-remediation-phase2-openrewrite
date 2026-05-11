import json
import uuid
import re
from datetime import datetime
from packaging import version
import argparse
from collections import defaultdict
import os

BASE_DIR = os.getcwd()


def safe_input_path(user_input):
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)


def safe_output_path(user_input):
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)


def extract_version(dep_string):
						   
									   
    if "@" in dep_string:
        dep_string = dep_string.split("@")[-1]

								  
    dep_string = re.sub(r'(\.RELEASE|\.FINAL|\.GA|\.SP\d+)$', '', dep_string, flags=re.IGNORECASE)
    dep_string = re.sub(r'[^0-9\.].*$', '', dep_string)

																
													   

    return dep_string.strip() if dep_string else "0"


def parse_code_scan(file_path):
    # 🔒 Snyk-compliant sanitization
    full_path = safe_input_path(file_path)

															 
										

    with open(full_path, encoding="utf-8") as f:
        data = json.load(f)

    code_map = {}

    runs = data.get("runs", [])

    for run in runs:
        rules = run["tool"]["driver"]["rules"]
        rule_map = {i: r for i, r in enumerate(rules)}

        for result in run.get("results", []):

            rule_index = result["ruleIndex"]
            rule = rule_map[rule_index]

            location = result["locations"][0]["physicalLocation"]

            rule_id = result["ruleId"]

            occurrence = {
                "file": location["artifactLocation"]["uri"],
                "line": location["region"]["startLine"]
            }

														  
            if rule_id not in code_map:
                code_map[rule_id] = {
                    "id": str(uuid.uuid4()),
                    "rule_id": rule_id,
                    "rule_name": rule["name"],
                    "severity": result.get("level", "medium"),
                    "description": rule["shortDescription"]["text"],
                    "cwe": rule["properties"].get("cwe", []),
                    "tags": rule["properties"].get("tags", []),
                    "occurrences": []
                }

            code_map[rule_id]["occurrences"].append(occurrence)

    return list(code_map.values())


def parse_dependency_scan(file_path):
    # 🔒 Snyk-compliant sanitization
    full_path = safe_input_path(file_path)

															 
										

    with open(full_path, encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", [])

												   

    dep_map = {}

    for vuln in vulnerabilities:

												 

        pkg = vuln["packageName"]
        current_version = vuln["version"]

        fix_version = "unknown"
        if vuln.get("upgradePath"):
            fix_version = vuln["upgradePath"][-1]

        elif vuln.get("nearestFixedInVersion"):
            fix_version = vuln["nearestFixedInVersion"]

        elif vuln.get("patched_versions"):
            fix_version = vuln["patched_versions"]

        elif vuln.get("fixedIn"):
            fix_version = vuln["fixedIn"][0]

        fix_ver = extract_version(fix_version)

        if pkg not in dep_map:

            dep_map[pkg] = {
                "id": str(uuid.uuid4()),
                "package": pkg,
                "current_version": current_version,
                "recommended_fix_version": fix_ver,
                "vulnerabilities": []
            }

        else:
            existing = dep_map[pkg]["recommended_fix_version"]

												   
            existing_ver = extract_version(existing)

																																

            if version.parse(fix_ver) > version.parse(existing_ver):
                dep_map[pkg]["recommended_fix_version"] = fix_ver

        dep_map[pkg]["vulnerabilities"].append({
            "id": vuln["id"],
            "title": vuln["title"],
            "severity": vuln["severity"],
            "cvss": vuln.get("cvssScore"),
            "cve": vuln.get("identifiers", {}).get("CVE", []),
            "cwe": vuln.get("identifiers", {}).get("CWE", []),
            "exploit": vuln.get("exploit"),
            "description": vuln["description"]
        })

												  

    return list(dep_map.values())


def build_summary(code, deps):
    return {
			   
        "total_dependencies": len(deps),
        "total_code_issues": len(code),
        "critical_count": 0,
        "high_count": len(deps),
        "medium_count": len(code),
        "low_count": 0
    }

				  


def build_output(code_issues, deps):
    return {
			  
        "scan_metadata": {
            "scanner": "snyk",
            "scan_time": datetime.utcnow().isoformat(),
            "project": "demo-project",
            "repository": "demo-repo",
            "branch": "main",
            "commit_id": "unknown"
        },
        "dependency_vulnerabilities": deps,
        "code_vulnerabilities": code_issues,
        "summary": build_summary(code_issues, deps)
    }

											 

				 


def main():

    parser = argparse.ArgumentParser(description="Normalize Snyk scan results")
    parser.add_argument("--code", required=True, help="Path to Snyk Code scan JSON")
    parser.add_argument("--deps", required=True, help="Path to Snyk dependency scan JSON")
    parser.add_argument("--output", required=True, help="Path to output normalized JSON")
    args = parser.parse_args()

    # 🔒 Sanitize all inputs using basename strategy
    code_path = safe_input_path(args.code)
    dep_path = safe_input_path(args.deps)
    output_path = safe_output_path(args.output)

													
										 
															
													  

    # Process
    code_issues = parse_code_scan(code_path)
    dependencies = parse_dependency_scan(dep_path)

    output = build_output(code_issues, dependencies)

												
											  
															   
														

    # Write output safely
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("Normalized scan written to:", output_path)



if __name__ == "__main__":
    main()
