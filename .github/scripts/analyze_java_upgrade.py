#!/usr/bin/env python3
"""
Java Upgrade Analyzer

Analyzes vulnerability findings and project configuration to determine if Java version
upgrade is required and recommend the optimal target version.

Usage:
    python analyze_java_upgrade.py <findings_file> <pom_file> <src_dir>

Output:
    java_upgrade_recommendation.json - JSON file containing upgrade recommendation
"""

import sys
import json
import os
import re
import requests
from typing import Dict, List, Any, Optional
from xml.etree import ElementTree as ET

# GitHub Models API configuration
GITHUB_TOKEN = ""
#AI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
AI_ENDPOINT="https://models.github.ai/inference/chat/completions"
AI_MODEL = "gpt-4o"


def extract_java_version(pom_path: str) -> str:
    """
    Parse current Java version from pom.xml.
    
    Args:
        pom_path: Path to pom.xml file
        
    Returns:
        Java version string (e.g., "1.8", "11", "17")
    """
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        
        # Define namespace
        ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
        
        # Try to find java.version property
        java_version = root.find('.//maven:properties/maven:java.version', ns)
        if java_version is not None and java_version.text:
            return java_version.text.strip()
        
        # Fallback to maven.compiler.source
        compiler_source = root.find('.//maven:properties/maven:maven.compiler.source', ns)
        if compiler_source is not None and compiler_source.text:
            return compiler_source.text.strip()
        
        # Default to Java 8 if not found
        return "1.8"
    except Exception as e:
        print(f"Warning: Failed to parse Java version from pom.xml: {e}")
        return "1.8"


def extract_spring_boot_version(pom_path: str) -> Optional[str]:
    """
    Parse Spring Boot version from pom.xml.
    
    Args:
        pom_path: Path to pom.xml file
        
    Returns:
        Spring Boot version string (e.g., "2.7.18", "3.0.0") or None if not found
    """
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        
        # Define namespace
        ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
        
        # Look for Spring Boot parent
        parent = root.find('.//maven:parent', ns)
        if parent is not None:
            artifact_id = parent.find('maven:artifactId', ns)
            version = parent.find('maven:version', ns)
            
            if (artifact_id is not None and 
                artifact_id.text == 'spring-boot-starter-parent' and
                version is not None and version.text):
                return version.text.strip()
        
        return None
    except Exception as e:
        print(f"Warning: Failed to parse Spring Boot version from pom.xml: {e}")
        return None


def normalize_java_version(version: str) -> int:
    """
    Normalize Java version string to integer for comparison.
    
    Args:
        version: Java version string (e.g., "1.8", "11", "17")
        
    Returns:
        Integer version (e.g., 8, 11, 17)
    """
    if version.startswith("1."):
        # Handle "1.8" format
        return int(version.split(".")[1])
    return int(version)


def get_fix_requirements(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Determine minimum Java version required for vulnerability fix using AI.
    
    This function uses GitHub Models API to intelligently analyze the vulnerability
    and determine if the fix requires a higher Java version.
    
    Args:
        vuln: Vulnerability finding dictionary
        
    Returns:
        Dictionary with 'min_java_version' (int) and 'requires_upgrade' (bool)
    """
    try:
        # Extract package details
        package_details = vuln.get('packageVulnerabilityDetails', {})
        vulnerable_packages = package_details.get('vulnerablePackages', [])
        
        if not vulnerable_packages:
            return {'min_java_version': 8, 'requires_upgrade': False}
        
        pkg = vulnerable_packages[0]
        package_name = pkg.get('name', '')
        current_version = pkg.get('version', '')
        fixed_version = pkg.get('fixedInVersion', '')
        cve = package_details.get('vulnerabilityId', 'UNKNOWN')
        
        # Use AI to determine Java version requirements
        if GITHUB_TOKEN:
            try:
                ai_result = analyze_dependency_with_ai(
                    package_name, 
                    current_version, 
                    fixed_version,
                    cve
                )
                if ai_result:
                    return ai_result
            except Exception as e:
                print(f"Warning: AI analysis failed for {package_name}, falling back to heuristics: {e}")
        
        # Fallback to heuristics if AI is not available
        # Spring Framework 6.x requires Java 17
        if 'spring-webmvc' in package_name or 'spring-web' in package_name:
            if fixed_version.startswith('6.'):
                return {'min_java_version': 17, 'requires_upgrade': True}
            elif fixed_version.startswith('5.'):
                return {'min_java_version': 8, 'requires_upgrade': False}
        
        # Spring Boot 3.x requires Java 17
        if 'spring-boot' in package_name:
            if fixed_version.startswith('3.'):
                return {'min_java_version': 17, 'requires_upgrade': True}
            elif fixed_version.startswith('2.'):
                return {'min_java_version': 8, 'requires_upgrade': False}
        
        # Jakarta EE (jakarta.*) requires Java 11+
        if 'jakarta' in package_name:
            return {'min_java_version': 11, 'requires_upgrade': True}
        
        # Most modern libraries work with Java 8
        return {'min_java_version': 8, 'requires_upgrade': False}
        
    except Exception as e:
        print(f"Warning: Failed to determine fix requirements for vulnerability: {e}")
        return {'min_java_version': 8, 'requires_upgrade': False}


def analyze_dependency_with_ai(package_name: str, current_version: str, 
                               fixed_version: str, cve: str) -> Optional[Dict[str, Any]]:
    """
    Use AI to analyze if a dependency upgrade requires a Java version upgrade.
    
    Args:
        package_name: Name of the package (e.g., "org.springframework:spring-webmvc")
        current_version: Current version of the package
        fixed_version: Fixed version that resolves the vulnerability
        cve: CVE identifier
        
    Returns:
        Dictionary with 'min_java_version' and 'requires_upgrade', or None if AI fails
    """
    prompt = f"""Analyze this Java dependency upgrade and determine the minimum Java version required.

Package: {package_name}
Current Version: {current_version}
Fixed Version: {fixed_version}
CVE: {cve}

Based on your knowledge of Java ecosystem compatibility:
1. Does the fixed version require Java 11 or higher?
2. Does the fixed version require Java 17 or higher?
3. What is the minimum Java version required?

Consider:
- Spring Framework 6.x requires Java 17
- Spring Boot 3.x requires Java 17
- Jakarta EE (jakarta.*) requires Java 11+
- Most libraries maintain Java 8 compatibility unless explicitly stated

Respond with ONLY a JSON object in this exact format:
{{"min_java_version": 8, "requires_upgrade": false, "reasoning": "brief explanation"}}

The min_java_version must be one of: 8, 11, or 17.
Set requires_upgrade to true only if min_java_version is greater than 8."""

    try:
        payload = {
            "model": AI_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a Java ecosystem expert. Analyze dependency upgrades and determine Java version requirements. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1  # Low temperature for consistent, factual responses
        }
        
        response = requests.post(
            AI_ENDPOINT,
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        
        ai_response = response.json()["choices"][0]["message"]["content"].strip()
        
        # Parse JSON response
        # Remove markdown code fences if present
        if ai_response.startswith("```"):
            ai_response = re.sub(r"^```json\n?", "", ai_response)
            ai_response = re.sub(r"\n?```$", "", ai_response).strip()
        
        result = json.loads(ai_response)
        
        # Validate response
        if 'min_java_version' in result and 'requires_upgrade' in result:
            min_version = int(result['min_java_version'])
            if min_version in [8, 11, 17]:
                print(f"  AI Analysis: {package_name} → Java {min_version} ({result.get('reasoning', 'No reasoning provided')})")
                return {
                    'min_java_version': min_version,
                    'requires_upgrade': bool(result['requires_upgrade'])
                }
        
        print(f"  Warning: Invalid AI response format for {package_name}")
        return None
        
    except Exception as e:
        print(f"  Warning: AI analysis failed for {package_name}: {e}")
        return None


def check_spring_boot_compatibility(spring_boot_version: Optional[str], 
                                    target_java: int) -> Dict[str, Any]:
    """
    Check Spring Boot compatibility with target Java version.
    
    Args:
        spring_boot_version: Current Spring Boot version (e.g., "2.7.18")
        target_java: Target Java version (8, 11, or 17)
        
    Returns:
        Dictionary with 'required' (bool) and 'target_version' (str or None)
    """
    if spring_boot_version is None:
        return {'required': False, 'target_version': None}
    
    try:
        major_version = int(spring_boot_version.split('.')[0])
        
        # Spring Boot 2.x is compatible with Java 8 and 11
        if major_version == 2:
            if target_java <= 11:
                return {'required': False, 'target_version': None}
            else:
                # Need to upgrade to Spring Boot 3.x for Java 17
                return {'required': True, 'target_version': '3.0.0'}
        
        # Spring Boot 3.x requires Java 17
        if major_version == 3:
            if target_java >= 17:
                return {'required': False, 'target_version': None}
            else:
                # Already on Spring Boot 3, no downgrade
                return {'required': False, 'target_version': None}
        
        return {'required': False, 'target_version': None}
        
    except Exception as e:
        print(f"Warning: Failed to check Spring Boot compatibility: {e}")
        return {'required': False, 'target_version': None}


def assess_migration_complexity(src_dir: str, current_java: int, 
                                target_java: int) -> str:
    """
    Assess migration complexity using AI-powered source code analysis.
    
    Args:
        src_dir: Path to source directory
        current_java: Current Java version (8, 11, or 17)
        target_java: Target Java version (8, 11, or 17)
        
    Returns:
        Complexity level: "LOW", "MEDIUM", or "HIGH"
    """
    if current_java == target_java:
        return "LOW"
    
    try:
        # Count Java files and gather statistics
        java_files = []
        for root, dirs, files in os.walk(src_dir):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))
        
        file_count = len(java_files)
        
        # Scan for complexity indicators
        javax_imports = 0
        deprecated_api_usage = 0
        java8_features = 0  # Lambda, streams, etc.
        
        # Sample files for AI analysis (max 5 files to avoid token limits)
        sample_files = []
        sample_size = min(5, len(java_files))
        
        for i, java_file in enumerate(java_files):
            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Count javax.* imports (will need jakarta migration for Java 17)
                    javax_count = len(re.findall(r'import\s+javax\.', content))
                    javax_imports += javax_count
                    
                    # Look for potentially deprecated APIs
                    deprecated_api_usage += len(re.findall(r'@Deprecated', content))
                    
                    # Look for Java 8 features
                    java8_features += len(re.findall(r'->|::|\bStream\b', content))
                    
                    # Collect sample files for AI analysis
                    if i < sample_size and len(content) < 5000:  # Limit file size
                        sample_files.append({
                            'path': os.path.basename(java_file),
                            'content': content[:2000]  # First 2000 chars
                        })
                    
            except Exception as e:
                print(f"Warning: Failed to analyze {java_file}: {e}")
                continue
        
        # Use AI for intelligent complexity assessment if available
        if GITHUB_TOKEN and sample_files:
            try:
                ai_complexity = analyze_complexity_with_ai(
                    current_java,
                    target_java,
                    file_count,
                    javax_imports,
                    deprecated_api_usage,
                    java8_features,
                    sample_files
                )
                if ai_complexity:
                    return ai_complexity
            except Exception as e:
                print(f"Warning: AI complexity analysis failed, using heuristics: {e}")
        
        # Fallback to heuristics
        if target_java == 17 and current_java == 8:
            # Java 8 -> 17 is a major jump
            if file_count > 50 or javax_imports > 20:
                return "HIGH"
            elif file_count > 20 or javax_imports > 5:
                return "MEDIUM"
            else:
                return "LOW"
        elif target_java == 11 and current_java == 8:
            # Java 8 -> 11 is moderate
            if file_count > 100:
                return "MEDIUM"
            else:
                return "LOW"
        else:
            return "LOW"
            
    except Exception as e:
        print(f"Warning: Failed to assess migration complexity: {e}")
        return "MEDIUM"


def analyze_complexity_with_ai(current_java: int, target_java: int, 
                               file_count: int, javax_imports: int,
                               deprecated_usage: int, java8_features: int,
                               sample_files: List[Dict[str, str]]) -> Optional[str]:
    """
    Use AI to analyze migration complexity based on code samples.
    
    Args:
        current_java: Current Java version
        target_java: Target Java version
        file_count: Total number of Java files
        javax_imports: Count of javax.* imports
        deprecated_usage: Count of @Deprecated annotations
        java8_features: Count of Java 8 features (lambdas, streams)
        sample_files: List of sample file dictionaries with 'path' and 'content'
        
    Returns:
        Complexity level: "LOW", "MEDIUM", or "HIGH", or None if AI fails
    """
    # Prepare code samples
    code_samples = "\n\n".join([
        f"File: {f['path']}\n{f['content'][:1000]}"  # Limit to 1000 chars per file
        for f in sample_files[:3]  # Max 3 files
    ])
    
    prompt = f"""Analyze the complexity of migrating this Java codebase from Java {current_java} to Java {target_java}.

Project Statistics:
- Total Java files: {file_count}
- javax.* imports: {javax_imports}
- Deprecated API usage: {deprecated_usage}
- Java 8 features (lambdas/streams): {java8_features}

Code Samples:
{code_samples}

Consider:
1. Java {current_java} → {target_java} migration scope
2. javax → jakarta migration needed for Java 17
3. Deprecated API replacements
4. Breaking changes in Java APIs
5. Code modernization opportunities

Assess the migration complexity as LOW, MEDIUM, or HIGH.

Respond with ONLY a JSON object:
{{"complexity": "LOW|MEDIUM|HIGH", "reasoning": "brief explanation", "key_challenges": ["challenge1", "challenge2"]}}"""

    try:
        payload = {
            "model": AI_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a Java migration expert. Analyze code and assess migration complexity. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.2
        }
        
        response = requests.post(
            AI_ENDPOINT,
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        
        ai_response = response.json()["choices"][0]["message"]["content"].strip()
        
        # Parse JSON response
        if ai_response.startswith("```"):
            ai_response = re.sub(r"^```json\n?", "", ai_response)
            ai_response = re.sub(r"\n?```$", "", ai_response).strip()
        
        result = json.loads(ai_response)
        
        if 'complexity' in result and result['complexity'] in ['LOW', 'MEDIUM', 'HIGH']:
            complexity = result['complexity']
            reasoning = result.get('reasoning', 'No reasoning provided')
            challenges = result.get('key_challenges', [])
            
            print(f"  AI Complexity Assessment: {complexity}")
            print(f"  Reasoning: {reasoning}")
            if challenges:
                print(f"  Key Challenges: {', '.join(challenges)}")
            
            return complexity
        
        print(f"  Warning: Invalid AI complexity response format")
        return None
        
    except Exception as e:
        print(f"  Warning: AI complexity analysis failed: {e}")
        return None


def get_java_compatible_version(package_name: str, fixed_version: str, 
                               target_java: int) -> str:
    """
    Determine the recommended version that's compatible with the target Java version.
    
    For packages that can be fixed in Java 8 but we're upgrading to Java 17,
    this function recommends a Java 17-compatible version instead of the minimum fix.
    
    Args:
        package_name: Name of the package (e.g., "io.netty:netty-handler")
        fixed_version: Minimum version that fixes the vulnerability
        target_java: Target Java version (8, 11, or 17)
        
    Returns:
        Recommended version string compatible with target Java version
    """
    # If staying on Java 8, use the minimum fix version
    if target_java == 8:
        return fixed_version
    
    # Use AI to determine Java-compatible version if available
    if GITHUB_TOKEN:
        try:
            ai_version = get_java_compatible_version_with_ai(
                package_name, 
                fixed_version, 
                target_java
            )
            if ai_version:
                return ai_version
        except Exception as e:
            print(f"  Warning: AI version recommendation failed for {package_name}, using heuristics: {e}")
    
    # Fallback to heuristics for common packages
    
    # Netty: Use latest 4.1.x for Java 17 compatibility
    if 'netty' in package_name.lower():
        if target_java >= 17:
            return "4.1.118.Final"  # Latest stable version tested with Java 17
        elif target_java >= 11:
            return "4.1.118.Final"
    
    # Spring Framework: Align with target Java version
    if 'spring-webmvc' in package_name or 'spring-web' in package_name:
        if target_java >= 17:
            return "6.1.8"  # Spring 6.x requires Java 17
        elif target_java >= 11:
            return "5.3.47"  # Latest Spring 5.x compatible with Java 11
    
    # Tomcat: Align with target Java version
    if 'tomcat-embed' in package_name:
        if target_java >= 17:
            return "10.1.31"  # Tomcat 10.x for Jakarta EE (Java 11+)
        elif target_java >= 11:
            return "9.0.117"  # Latest Tomcat 9.x compatible with Java 11
    
    # Default: use the minimum fix version
    return fixed_version


def get_java_compatible_version_with_ai(package_name: str, fixed_version: str,
                                        target_java: int) -> Optional[str]:
    """
    Use AI to determine the recommended version compatible with target Java version.
    
    Args:
        package_name: Name of the package
        fixed_version: Minimum version that fixes the vulnerability
        target_java: Target Java version (8, 11, or 17)
        
    Returns:
        Recommended version string, or None if AI fails
    """
    prompt = f"""Recommend the optimal version for this Java dependency when upgrading to Java {target_java}.

Package: {package_name}
Minimum Fix Version: {fixed_version}
Target Java Version: {target_java}

Consider:
1. The minimum fix version addresses the vulnerability
2. We're upgrading to Java {target_java}
3. We want a version that's tested and certified for Java {target_java}
4. We prefer stable, production-ready versions

For example:
- If Netty 4.1.118.Final fixes the CVE and we're upgrading to Java 17, recommend 4.1.118.Final (tested with Java 17)
- If Spring 5.3.47 fixes the CVE but we're upgrading to Java 17, recommend Spring 6.1.8 (requires Java 17)
- If Tomcat 9.0.117 fixes the CVE but we're upgrading to Java 17, recommend Tomcat 10.1.31 (Jakarta EE, Java 11+)

Respond with ONLY a JSON object:
{{"recommended_version": "version_string", "reasoning": "brief explanation"}}"""

    try:
        payload = {
            "model": AI_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a Java ecosystem expert. Recommend dependency versions that align with target Java versions. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1
        }
        
        response = requests.post(
            AI_ENDPOINT,
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        
        ai_response = response.json()["choices"][0]["message"]["content"].strip()
        
        # Parse JSON response
        if ai_response.startswith("```"):
            ai_response = re.sub(r"^```json\n?", "", ai_response)
            ai_response = re.sub(r"\n?```$", "", ai_response).strip()
        
        result = json.loads(ai_response)
        
        if 'recommended_version' in result:
            recommended = result['recommended_version']
            reasoning = result.get('reasoning', 'No reasoning provided')
            print(f"  AI Version Recommendation: {package_name} → {recommended} ({reasoning})")
            return recommended
        
        print(f"  Warning: Invalid AI version recommendation response for {package_name}")
        return None
        
    except Exception as e:
        print(f"  Warning: AI version recommendation failed for {package_name}: {e}")
        return None


def calculate_confidence(vulns_requiring_upgrade: List[Dict[str, Any]], 
                        complexity: str) -> float:
    """
    Calculate confidence score for the upgrade recommendation.
    
    Args:
        vulns_requiring_upgrade: List of vulnerabilities requiring upgrade
        complexity: Migration complexity level
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    # Base confidence on number of vulnerabilities
    vuln_count = len(vulns_requiring_upgrade)
    
    if vuln_count == 0:
        return 1.0  # High confidence in staying on current version
    
    # Start with base confidence
    confidence = 0.7
    
    # Increase confidence with more vulnerabilities requiring upgrade
    if vuln_count >= 5:
        confidence += 0.2
    elif vuln_count >= 3:
        confidence += 0.15
    elif vuln_count >= 1:
        confidence += 0.1
    
    # Adjust based on complexity
    if complexity == "LOW":
        confidence += 0.1
    elif complexity == "HIGH":
        confidence -= 0.1
    
    # Ensure confidence is between 0.0 and 1.0
    return max(0.0, min(1.0, confidence))


def generate_rationale(vulns_requiring_upgrade: List[Dict[str, Any]]) -> str:
    """
    Generate human-readable rationale for the upgrade decision.
    
    Args:
        vulns_requiring_upgrade: List of vulnerabilities requiring upgrade
        
    Returns:
        Rationale string
    """
    if not vulns_requiring_upgrade:
        return "All vulnerabilities can be fixed in the current Java version"
    
    vuln_count = len(vulns_requiring_upgrade)
    
    # Count by severity
    critical_count = sum(1 for v in vulns_requiring_upgrade 
                        if v.get('severity') == 'CRITICAL')
    high_count = sum(1 for v in vulns_requiring_upgrade 
                    if v.get('severity') == 'HIGH')
    
    severity_text = []
    if critical_count > 0:
        severity_text.append(f"{critical_count} critical")
    if high_count > 0:
        severity_text.append(f"{high_count} high")
    
    if severity_text:
        severity_str = " and ".join(severity_text) + "-severity"
    else:
        severity_str = ""
    
    if vuln_count == 1:
        return f"1 {severity_str} vulnerability requires Java version upgrade"
    else:
        return f"{vuln_count} {severity_str} vulnerabilities require Java version upgrade"


def analyze_java_upgrade(findings_path: str, pom_path: str, src_dir: str) -> Dict[str, Any]:
    """
    Main analysis function that determines if Java upgrade is required.
    
    Args:
        findings_path: Path to normalized vulnerability findings JSON (or raw AWS Inspector JSON)
        pom_path: Path to pom.xml
        src_dir: Path to source directory
        
    Returns:
        Dictionary containing upgrade recommendation and analysis details
    """
    # Step 1: Extract current Java version from pom.xml
    current_java_str = extract_java_version(pom_path)
    current_java = normalize_java_version(current_java_str)
    
    print(f"Current Java version: {current_java_str} (normalized: {current_java})")
    
    # Step 2: Extract Spring Boot version
    spring_boot_version = extract_spring_boot_version(pom_path)
    print(f"Spring Boot version: {spring_boot_version}")
    
    # Step 3: Load vulnerability findings
    try:
        with open(findings_path, 'r') as f:
            findings = json.load(f)
    except Exception as e:
        print(f"Error: Failed to load findings file: {e}")
        return {
            "recommendation": "STAY_JAVA_8",
            "confidence": 0.5,
            "current_java_version": current_java_str,
            "error": str(e)
        }
    
    # Step 4: Detect format and extract vulnerabilities
    # Support both raw AWS Inspector format and normalized format
    vulnerabilities = []
    
    if 'findings' in findings:
        # Raw AWS Inspector format
        print("Detected: Raw AWS Inspector format")
        vulnerabilities = findings.get('findings', [])
    elif 'dependency_vulnerabilities' in findings:
        # Normalized format - convert to expected structure
        print("Detected: Normalized format")
        for vuln in findings.get('dependency_vulnerabilities', []):
            # Convert normalized format to expected structure
            converted_vuln = {
                'severity': vuln.get('severity', 'UNKNOWN').upper(),
                'packageVulnerabilityDetails': {
                    'vulnerabilityId': vuln.get('cve', ['UNKNOWN'])[0] if vuln.get('cve') else 'UNKNOWN',
                    'vulnerablePackages': [{
                        'name': vuln.get('package_name', 'UNKNOWN'),
                        'version': vuln.get('current_version', 'UNKNOWN'),
                        'fixedInVersion': vuln.get('fixed_version', 'UNKNOWN')
                    }]
                }
            }
            vulnerabilities.append(converted_vuln)
    else:
        print("Warning: Unknown findings format, expected 'findings' or 'dependency_vulnerabilities' key")
        return {
            "recommendation": "STAY_JAVA_8",
            "confidence": 0.5,
            "current_java_version": current_java_str,
            "error": "Unknown findings format"
        }
    
    print(f"Found {len(vulnerabilities)} vulnerabilities to analyze")
    
    # Step 5: Analyze each vulnerability (first pass - determine target Java version)
    upgrade_required_vulns = []
    all_vulns_initial = []
    
    for vuln in vulnerabilities:
        fix_info = get_fix_requirements(vuln)
        
        # Extract vulnerability details
        package_details = vuln.get('packageVulnerabilityDetails', {})
        vulnerable_packages = package_details.get('vulnerablePackages', [])
        
        if vulnerable_packages:
            pkg = vulnerable_packages[0]
            vuln_detail = {
                'cve': package_details.get('vulnerabilityId', 'UNKNOWN'),
                'package': pkg.get('name', 'UNKNOWN'),
                'current_version': pkg.get('version', 'UNKNOWN'),
                'fixed_version': pkg.get('fixedInVersion', 'UNKNOWN'),
                'min_java_version': str(fix_info['min_java_version']),
                'severity': vuln.get('severity', 'UNKNOWN')
            }
            
            # Add to initial list
            all_vulns_initial.append(vuln_detail)
            
            # Add to upgrade-required list only if it requires higher Java version
            if fix_info['min_java_version'] > current_java:
                upgrade_required_vulns.append(vuln_detail)
    
    print(f"Total vulnerabilities found: {len(all_vulns_initial)}")
    print(f"Vulnerabilities requiring upgrade: {len(upgrade_required_vulns)}")
    
    # Step 6: Determine target Java version
    if not upgrade_required_vulns:
        recommendation = "STAY_JAVA_8"
        target_java = current_java
        target_java_str = current_java_str
    else:
        # Find minimum Java version that fixes all vulnerabilities
        required_versions = [int(v['min_java_version']) for v in upgrade_required_vulns]
        target_java = max(required_versions)
        target_java_str = str(target_java)
        
        if target_java == 11:
            recommendation = "UPGRADE_JAVA_11"
        elif target_java >= 17:
            recommendation = "UPGRADE_JAVA_17"
            target_java = 17
            target_java_str = "17"
        else:
            recommendation = "STAY_JAVA_8"
            target_java = current_java
            target_java_str = current_java_str
    
    # Step 6.5: Update fixed versions to be compatible with target Java version
    print(f"\nAligning dependency versions with Java {target_java}...")
    all_vulns_addressed = []
    
    for vuln_detail in all_vulns_initial:
        # Get Java-compatible version
        compatible_version = get_java_compatible_version(
            vuln_detail['package'],
            vuln_detail['fixed_version'],
            target_java
        )
        
        # Update the fixed version if it changed
        if compatible_version != vuln_detail['fixed_version']:
            print(f"  {vuln_detail['package']}: {vuln_detail['fixed_version']} → {compatible_version} (Java {target_java} compatible)")
            vuln_detail['fixed_version'] = compatible_version
        
        all_vulns_addressed.append(vuln_detail)
    
    # Step 7: Check Spring Boot compatibility
    spring_boot_upgrade = check_spring_boot_compatibility(spring_boot_version, target_java)
    
    # Step 8: Assess migration complexity
    complexity = assess_migration_complexity(src_dir, current_java, target_java)
    
    # Step 9: Calculate confidence
    confidence = calculate_confidence(upgrade_required_vulns, complexity)
    
    # Step 10: Generate rationale
    rationale = generate_rationale(upgrade_required_vulns)
    
    # Step 11: Build recommendation
    result = {
        "recommendation": recommendation,
        "confidence": confidence,
        "current_java_version": current_java_str,
        "target_java_version": target_java_str,
        "rationale": rationale,
        "vulnerabilities_requiring_upgrade": upgrade_required_vulns,
        "all_vulnerabilities_addressed": all_vulns_addressed,
        "spring_boot_upgrade_required": spring_boot_upgrade['required'],
        "target_spring_boot_version": spring_boot_upgrade['target_version'],
        "migration_complexity": complexity
    }
    
    return result


def main():
    """Main entry point for the script."""
    if len(sys.argv) != 4:
        print("Usage: python analyze_java_upgrade.py <findings_file> <pom_file> <src_dir>")
        sys.exit(1)
    
    findings_file = sys.argv[1]
    pom_file = sys.argv[2]
    src_dir = sys.argv[3]
    
    # Validate inputs
    if not os.path.exists(findings_file):
        print(f"Error: Findings file not found: {findings_file}")
        sys.exit(1)
    
    if not os.path.exists(pom_file):
        print(f"Error: POM file not found: {pom_file}")
        sys.exit(1)
    
    if not os.path.exists(src_dir):
        print(f"Error: Source directory not found: {src_dir}")
        sys.exit(1)
    
    print("=" * 60)
    print("Java Upgrade Analyzer")
    print("=" * 60)
    
    # Run analysis
    recommendation = analyze_java_upgrade(findings_file, pom_file, src_dir)
    
    # Write output
    output_file = "java_upgrade_recommendation.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(recommendation, f, indent=2)
        print(f"\nAnalysis complete. Recommendation written to {output_file}")
        print(f"\nRecommendation: {recommendation['recommendation']}")
        print(f"Confidence: {recommendation['confidence']:.2f}")
        print(f"Rationale: {recommendation['rationale']}")
    except Exception as e:
        print(f"Error: Failed to write recommendation file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
