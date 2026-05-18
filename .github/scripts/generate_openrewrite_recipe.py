#!/usr/bin/env python3
"""
OpenRewrite Recipe Generator

This script generates OpenRewrite recipe configuration files for Java version migrations
based on the Java upgrade recommendation. It creates rewrite.yml files and updates
pom.xml with the necessary OpenRewrite plugin configuration.

Uses AI to intelligently select recipes based on project analysis.

Usage:
    python generate_openrewrite_recipe.py <recommendation_file> <pom_file> <src_dir>

Arguments:
    recommendation_file: Path to java_upgrade_recommendation.json
    pom_file: Path to pom.xml
    src_dir: Path to source directory

Outputs:
    - rewrite.yml: OpenRewrite recipe configuration
    - Updated pom.xml with OpenRewrite plugin configuration
"""

import json
import sys
import yaml
import os
import re
import requests
from lxml import etree
from pathlib import Path
from typing import Dict, List, Any, Optional

# GitHub Models API configuration
GITHUB_TOKEN = ""
AI_ENDPOINT="https://models.github.ai/inference/chat/completions"
#AI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
AI_MODEL = "gpt-4o"

# OpenRewrite recipe template for Java 8 to Java 11 migration
JAVA_11_RECIPE_TEMPLATE = {
    'type': 'specs.openrewrite.org/v1beta/recipe',
    'name': 'com.example.MigrateToJava11',
    'displayName': 'Migrate to Java 11',
    'description': 'Migrates Java 8 code to Java 11',
    'recipeList': [
        'org.openrewrite.java.migrate.Java8toJava11',
        'org.openrewrite.java.migrate.UpgradeBuildToJava11',
        'org.openrewrite.java.migrate.javax.AddJaxbRuntime',
        'org.openrewrite.java.migrate.javax.AddJaxwsRuntime',
        'org.openrewrite.java.migrate.UpgradePluginsForJava11'
    ]
}

# OpenRewrite recipe template for Java 8 to Java 17 migration
JAVA_17_RECIPE_TEMPLATE = {
    'type': 'specs.openrewrite.org/v1beta/recipe',
    'name': 'com.example.MigrateToJava17',
    'displayName': 'Migrate to Java 17',
    'description': 'Migrates Java 8 code to Java 17',
    'recipeList': [
        'org.openrewrite.java.migrate.UpgradeToJava17',
        'org.openrewrite.java.migrate.javax.AddJaxbRuntime',
        'org.openrewrite.java.migrate.javax.AddJaxwsRuntime'
    ]
}

# Spring Boot 3 upgrade recipes
SPRING_BOOT_3_RECIPES = [
    'org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0',
    'org.openrewrite.java.migrate.jakarta.JavaxMigrationToJakarta'
]

# Available OpenRewrite recipes by category
AVAILABLE_RECIPES = {
    'java_11_core': [
        'org.openrewrite.java.migrate.Java8toJava11',
        'org.openrewrite.java.migrate.UpgradeBuildToJava11',
        'org.openrewrite.java.migrate.UpgradePluginsForJava11'
    ],
    'java_17_core': [
        'org.openrewrite.java.migrate.UpgradeToJava17'
    ],
    'javax_jaxb': [
        'org.openrewrite.java.migrate.javax.AddJaxbRuntime',
        'org.openrewrite.java.migrate.javax.AddJaxbDependencies'
    ],
    'javax_jaxws': [
        'org.openrewrite.java.migrate.javax.AddJaxwsRuntime'
    ],
    'javax_annotation': [
        'org.openrewrite.java.migrate.javax.AddJavaxAnnotationApi'
    ],
    'jakarta_migration': [
        'org.openrewrite.java.migrate.jakarta.JavaxMigrationToJakarta',
        'org.openrewrite.java.migrate.jakarta.JavaxPersistenceToJakartaPersistence',
        'org.openrewrite.java.migrate.jakarta.JavaxServletToJakartaServlet'
    ],
    'spring_boot_3': [
        'org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0',
        'org.openrewrite.java.spring.boot3.SpringBoot3BestPractices'
    ],
    'spring_security_6': [
        'org.openrewrite.java.spring.security6.UpgradeSpring Security_6_0'
    ],
    'hibernate_6': [
        'org.openrewrite.java.migrate.hibernate.MigrateToHibernate60'
    ],
    'lombok': [
        'org.openrewrite.java.migrate.lombok.UpdateLombokToJava11',
        'org.openrewrite.java.migrate.lombok.UpdateLombokToJava17'
    ]
}


def analyze_project_patterns(src_dir: str, pom_file: str) -> Dict[str, Any]:
    """
    Analyze project to detect frameworks, libraries, and code patterns.
    
    Args:
        src_dir: Path to source directory
        pom_file: Path to pom.xml
        
    Returns:
        Dictionary with detected patterns
    """
    patterns = {
        'has_javax_imports': False,
        'has_javax_persistence': False,
        'has_javax_servlet': False,
        'has_javax_annotation': False,
        'has_jaxb': False,
        'has_jaxws': False,
        'has_spring_boot': False,
        'has_spring_security': False,
        'has_hibernate': False,
        'has_lombok': False,
        'java_file_count': 0,
        'sample_files': []
    }
    
    # Analyze source files
    java_files = []
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.java'):
                java_files.append(os.path.join(root, file))
    
    patterns['java_file_count'] = len(java_files)
    
    # Sample up to 5 files for detailed analysis
    sample_size = min(5, len(java_files))
    for i, java_file in enumerate(java_files[:sample_size]):
        try:
            with open(java_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Detect javax imports
                if re.search(r'import\s+javax\.', content):
                    patterns['has_javax_imports'] = True
                
                if re.search(r'import\s+javax\.persistence\.', content):
                    patterns['has_javax_persistence'] = True
                
                if re.search(r'import\s+javax\.servlet\.', content):
                    patterns['has_javax_servlet'] = True
                
                if re.search(r'import\s+javax\.annotation\.', content):
                    patterns['has_javax_annotation'] = True
                
                if re.search(r'import\s+javax\.xml\.bind\.', content):
                    patterns['has_jaxb'] = True
                
                if re.search(r'import\s+javax\.xml\.ws\.', content):
                    patterns['has_jaxws'] = True
                
                if re.search(r'import\s+org\.springframework\.', content):
                    patterns['has_spring_boot'] = True
                
                if re.search(r'import\s+org\.springframework\.security\.', content):
                    patterns['has_spring_security'] = True
                
                if re.search(r'import\s+org\.hibernate\.', content):
                    patterns['has_hibernate'] = True
                
                if re.search(r'import\s+lombok\.', content):
                    patterns['has_lombok'] = True
                
                # Collect sample for AI analysis
                if len(content) < 5000:
                    patterns['sample_files'].append({
                        'path': os.path.basename(java_file),
                        'content': content[:2000]
                    })
        except Exception as e:
            print(f"Warning: Failed to analyze {java_file}: {e}")
            continue
    
    # Analyze POM for dependencies
    try:
        tree = etree.parse(pom_file)
        root = tree.getroot()
        ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
        
        dependencies = root.findall('.//maven:dependency', ns)
        for dep in dependencies:
            group_id = dep.find('maven:groupId', ns)
            artifact_id = dep.find('maven:artifactId', ns)
            
            if group_id is not None and artifact_id is not None:
                group = group_id.text
                artifact = artifact_id.text
                
                if 'spring-boot' in artifact:
                    patterns['has_spring_boot'] = True
                if 'spring-security' in artifact:
                    patterns['has_spring_security'] = True
                if 'hibernate' in artifact:
                    patterns['has_hibernate'] = True
                if 'lombok' in artifact:
                    patterns['has_lombok'] = True
    except Exception as e:
        print(f"Warning: Failed to analyze POM dependencies: {e}")
    
    return patterns


def select_recipes_with_ai(target_version: str, spring_boot_upgrade: bool,
                          patterns: Dict[str, Any]) -> Optional[List[str]]:
    """
    Use AI to intelligently select OpenRewrite recipes based on project analysis.
    
    Args:
        target_version: Target Java version (11 or 17)
        spring_boot_upgrade: Whether Spring Boot upgrade is required
        patterns: Detected project patterns
        
    Returns:
        List of recipe names, or None if AI fails
    """
    if not GITHUB_TOKEN:
        print("  Warning: GITHUB_TOKEN not set, using heuristic recipe selection")
        return None
    
    # Prepare project analysis summary
    analysis_summary = f"""
Target Java Version: {target_version}
Spring Boot Upgrade Required: {spring_boot_upgrade}

Project Analysis:
- Java files: {patterns['java_file_count']}
- Has javax.* imports: {patterns['has_javax_imports']}
- Has javax.persistence: {patterns['has_javax_persistence']}
- Has javax.servlet: {patterns['has_javax_servlet']}
- Has javax.annotation: {patterns['has_javax_annotation']}
- Has JAXB: {patterns['has_jaxb']}
- Has JAX-WS: {patterns['has_jaxws']}
- Has Spring Boot: {patterns['has_spring_boot']}
- Has Spring Security: {patterns['has_spring_security']}
- Has Hibernate: {patterns['has_hibernate']}
- Has Lombok: {patterns['has_lombok']}
"""
    
    # Add code samples if available
    if patterns['sample_files']:
        code_samples = "\n\n".join([
            f"File: {f['path']}\n{f['content'][:1000]}"
            for f in patterns['sample_files'][:2]
        ])
        analysis_summary += f"\n\nCode Samples:\n{code_samples}"
    
    prompt = f"""You are an OpenRewrite expert. Select the optimal OpenRewrite recipes for this Java migration project.

{analysis_summary}

Available Recipe Categories:
{json.dumps(AVAILABLE_RECIPES, indent=2)}

Instructions:
1. Select recipes that are ACTUALLY NEEDED based on the project analysis
2. Include core migration recipes for Java {target_version}
3. Include javax → jakarta recipes ONLY if javax imports are detected
4. Include framework-specific recipes ONLY if those frameworks are detected
5. Prioritize recipes by importance (most critical first)
6. Avoid including recipes for frameworks/libraries not used in the project

Respond with ONLY a JSON object:
{{
  "recipes": ["recipe1", "recipe2", ...],
  "reasoning": "Brief explanation of why each recipe category was included or excluded"
}}"""

    try:
        payload = {
            "model": AI_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an OpenRewrite expert. Select optimal recipes based on project analysis. Always respond with valid JSON only."
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
        
        if 'recipes' in result and isinstance(result['recipes'], list):
            recipes = result['recipes']
            reasoning = result.get('reasoning', 'No reasoning provided')
            
            print(f"\n  AI Recipe Selection:")
            print(f"  Selected {len(recipes)} recipes")
            print(f"  Reasoning: {reasoning}\n")
            
            return recipes
        
        print("  Warning: Invalid AI recipe selection response")
        return None
        
    except Exception as e:
        print(f"  Warning: AI recipe selection failed: {e}")
        return None


def select_recipes_heuristic(target_version: str, spring_boot_upgrade: bool,
                             patterns: Dict[str, Any]) -> List[str]:
    """
    Fallback heuristic recipe selection based on project patterns.
    
    Args:
        target_version: Target Java version (11 or 17)
        spring_boot_upgrade: Whether Spring Boot upgrade is required
        patterns: Detected project patterns
        
    Returns:
        List of recipe names
    """
    recipes = []
    
    # Core Java migration recipes
    if target_version == '11':
        recipes.extend(AVAILABLE_RECIPES['java_11_core'])
    elif target_version == '17':
        recipes.extend(AVAILABLE_RECIPES['java_17_core'])
    
    # javax.* runtime dependencies
    if patterns['has_jaxb']:
        recipes.extend(AVAILABLE_RECIPES['javax_jaxb'])
    
    if patterns['has_jaxws']:
        recipes.extend(AVAILABLE_RECIPES['javax_jaxws'])
    
    if patterns['has_javax_annotation']:
        recipes.extend(AVAILABLE_RECIPES['javax_annotation'])
    
    # Jakarta migration (for Java 17 with javax imports)
    if target_version == '17' and patterns['has_javax_imports']:
        recipes.extend(AVAILABLE_RECIPES['jakarta_migration'])
    
    # Spring Boot 3 migration
    if spring_boot_upgrade:
        recipes.extend(AVAILABLE_RECIPES['spring_boot_3'])
    
    # Spring Security 6 (if Spring Boot 3 upgrade)
    if spring_boot_upgrade and patterns['has_spring_security']:
        recipes.extend(AVAILABLE_RECIPES['spring_security_6'])
    
    # Hibernate 6 (if upgrading to Java 17 with Hibernate)
    if target_version == '17' and patterns['has_hibernate']:
        recipes.extend(AVAILABLE_RECIPES['hibernate_6'])
    
    # Lombok updates
    if patterns['has_lombok']:
        if target_version == '17':
            recipes.append('org.openrewrite.java.migrate.lombok.UpdateLombokToJava17')
        elif target_version == '11':
            recipes.append('org.openrewrite.java.migrate.lombok.UpdateLombokToJava11')
    
    return recipes


def write_yaml(filename, recipe):
    """
    Write recipe configuration to YAML file.
    
    Args:
        filename (str): Output filename
        recipe (dict): Recipe configuration dictionary
    """
    with open(filename, 'w') as f:
        yaml.dump(recipe, f, default_flow_style=False, sort_keys=False)
    print(f"✓ Recipe file written to {filename}")


def add_openrewrite_plugin(pom_file, recipe_name, dependencies):
    """
    Add or update OpenRewrite Maven plugin configuration in pom.xml.
    
    Args:
        pom_file (str): Path to pom.xml
        recipe_name (str): Name of the recipe to activate
        dependencies (list): List of OpenRewrite dependency artifact IDs
    """
    # Parse POM with namespace handling
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(pom_file, parser)
    root = tree.getroot()
    
    # Define namespace
    ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
    
    # Get the default namespace from the root element
    default_ns = root.nsmap.get(None, 'http://maven.apache.org/POM/4.0.0')
    
    # Helper function to create elements with proper namespace
    def make_element(tag):
        return etree.Element(f'{{{default_ns}}}{tag}')
    
    # Find or create build section
    build = root.find('maven:build', ns)
    if build is None:
        build = make_element('build')
        root.append(build)
    
    # Find or create plugins section
    plugins = build.find('maven:plugins', ns)
    if plugins is None:
        plugins = make_element('plugins')
        build.append(plugins)
    
    # Check if OpenRewrite plugin already exists
    existing_plugin = None
    for plugin in plugins.findall('maven:plugin', ns):
        group_id = plugin.find('maven:groupId', ns)
        artifact_id = plugin.find('maven:artifactId', ns)
        if (group_id is not None and group_id.text == 'org.openrewrite.maven' and
            artifact_id is not None and artifact_id.text == 'rewrite-maven-plugin'):
            existing_plugin = plugin
            break
    
    if existing_plugin is not None:
        print("✓ OpenRewrite plugin already exists, updating configuration")
        plugin = existing_plugin
        # Remove old configuration and dependencies to replace them
        old_config = plugin.find('maven:configuration', ns)
        if old_config is not None:
            plugin.remove(old_config)
        old_deps = plugin.find('maven:dependencies', ns)
        if old_deps is not None:
            plugin.remove(old_deps)
    else:
        print("✓ Adding OpenRewrite plugin to pom.xml")
        plugin = make_element('plugin')
        plugins.append(plugin)
        
        # Add groupId, artifactId, version
        group_id = make_element('groupId')
        group_id.text = 'org.openrewrite.maven'
        plugin.append(group_id)
        
        artifact_id = make_element('artifactId')
        artifact_id.text = 'rewrite-maven-plugin'
        plugin.append(artifact_id)
        
        version = make_element('version')
        version.text = '5.42.0'
        plugin.append(version)
    
    # Add configuration
    configuration = make_element('configuration')
    plugin.append(configuration)
    
    active_recipes = make_element('activeRecipes')
    configuration.append(active_recipes)
    
    recipe = make_element('recipe')
    recipe.text = recipe_name
    active_recipes.append(recipe)
    
    # Add dependencies
    plugin_dependencies = make_element('dependencies')
    plugin.append(plugin_dependencies)
    
    # Dependency version mapping
    dependency_versions = {
        'rewrite-migrate-java': '2.26.1',
        'rewrite-spring': '5.21.0'
    }
    
    for dep_artifact_id in dependencies:
        dependency = make_element('dependency')
        plugin_dependencies.append(dependency)
        
        dep_group_id = make_element('groupId')
        dep_group_id.text = 'org.openrewrite.recipe'
        dependency.append(dep_group_id)
        
        dep_artifact = make_element('artifactId')
        dep_artifact.text = dep_artifact_id
        dependency.append(dep_artifact)
        
        dep_version = make_element('version')
        dep_version.text = dependency_versions.get(dep_artifact_id, '2.26.1')
        dependency.append(dep_version)
    
    # Write updated POM
    tree.write(pom_file, encoding='utf-8', xml_declaration=True, pretty_print=True)
    print(f"✓ Updated {pom_file} with OpenRewrite plugin configuration")


def generate_recipe(recommendation, pom_file, src_dir):
    """
    Generate OpenRewrite recipe based on Java upgrade recommendation.
    
    Uses AI to intelligently select recipes based on project analysis.
    
    Args:
        recommendation (dict): Java upgrade recommendation from analyzer
        pom_file (str): Path to pom.xml
        src_dir (str): Path to source directory
    
    Returns:
        dict: Recipe generation result with recipe_file, recipe_name, and dependencies
    """
    target_version = recommendation.get('target_java_version')
    spring_boot_upgrade = recommendation.get('spring_boot_upgrade_required', False)
    
    print("\nAnalyzing project patterns...")
    patterns = analyze_project_patterns(src_dir, pom_file)
    
    print(f"  Found {patterns['java_file_count']} Java files")
    print(f"  javax imports: {patterns['has_javax_imports']}")
    print(f"  Spring Boot: {patterns['has_spring_boot']}")
    print(f"  Hibernate: {patterns['has_hibernate']}")
    
    # Try AI-powered recipe selection first
    print("\nSelecting OpenRewrite recipes...")
    recipes = select_recipes_with_ai(target_version, spring_boot_upgrade, patterns)
    
    # Fallback to heuristics if AI fails
    if recipes is None:
        print("  Using heuristic recipe selection")
        recipes = select_recipes_heuristic(target_version, spring_boot_upgrade, patterns)
    
    # Build recipe configuration
    if target_version == '11':
        recipe_name = 'com.example.MigrateToJava11'
        display_name = 'Migrate to Java 11'
        description = 'Migrates Java 8 code to Java 11'
    elif target_version == '17':
        if spring_boot_upgrade:
            recipe_name = 'com.example.MigrateToJava17WithSpringBoot3'
            display_name = 'Migrate to Java 17 with Spring Boot 3'
            description = 'Migrates Java 8 code to Java 17 and Spring Boot 3'
        else:
            recipe_name = 'com.example.MigrateToJava17'
            display_name = 'Migrate to Java 17'
            description = 'Migrates Java 8 code to Java 17'
    else:
        print(f"✗ Unsupported target Java version: {target_version}")
        sys.exit(1)
    
    recipe = {
        'type': 'specs.openrewrite.org/v1beta/recipe',
        'name': recipe_name,
        'displayName': display_name,
        'description': description,
        'recipeList': recipes
    }
    
    # Determine required dependencies
    dependencies = ['rewrite-migrate-java']
    if spring_boot_upgrade or any('spring' in r.lower() for r in recipes):
        dependencies.append('rewrite-spring')
    
    print(f"\n  Selected {len(recipes)} recipes:")
    for r in recipes:
        print(f"    - {r}")
    
    # Write rewrite.yml
    write_yaml('rewrite.yml', recipe)
    
    # Update pom.xml with plugin configuration
    add_openrewrite_plugin(pom_file, recipe['name'], dependencies)
    
    return {
        'recipe_file': 'rewrite.yml',
        'recipe_name': recipe['name'],
        'dependencies': dependencies,
        'recipe_count': len(recipes)
    }


def main():
    """Main entry point for the script."""
    if len(sys.argv) != 4:
        print("Usage: python generate_openrewrite_recipe.py <recommendation_file> <pom_file> <src_dir>")
        sys.exit(1)
    
    recommendation_file = sys.argv[1]
    pom_file = sys.argv[2]
    src_dir = sys.argv[3]
    
    # Validate input files exist
    if not Path(recommendation_file).exists():
        print(f"✗ Recommendation file not found: {recommendation_file}")
        sys.exit(1)
    
    if not Path(pom_file).exists():
        print(f"✗ POM file not found: {pom_file}")
        sys.exit(1)
    
    if not Path(src_dir).exists():
        print(f"✗ Source directory not found: {src_dir}")
        sys.exit(1)
    
    # Load recommendation
    with open(recommendation_file, 'r') as f:
        recommendation = json.load(f)
    
    print("=" * 60)
    print("OpenRewrite Recipe Generator (AI-Powered)")
    print("=" * 60)
    print(f"Recommendation: {recommendation.get('recommendation')}")
    print(f"Target Java Version: {recommendation.get('target_java_version')}")
    print(f"Spring Boot Upgrade Required: {recommendation.get('spring_boot_upgrade_required')}")
    print("=" * 60)
    
    # Generate recipe
    result = generate_recipe(recommendation, pom_file, src_dir)
    
    print("\n" + "=" * 60)
    print("Recipe Generation Complete")
    print("=" * 60)
    print(f"Recipe File: {result['recipe_file']}")
    print(f"Recipe Name: {result['recipe_name']}")
    print(f"Recipe Count: {result['recipe_count']}")
    print(f"Dependencies: {', '.join(result['dependencies'])}")
    print("=" * 60)


if __name__ == '__main__':
    main()
