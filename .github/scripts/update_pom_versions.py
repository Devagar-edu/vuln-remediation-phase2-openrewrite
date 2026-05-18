#!/usr/bin/env python3
"""
POM Version Updater

This script updates pom.xml with target Java version and Spring Boot version
based on the java_upgrade_recommendation.json file.

Functions:
- parse_xml(pom_file): Parse pom.xml using lxml
- update_property(tree, property_name, value): Update a property value
- update_parent_version(tree, artifact_id, version): Update parent version
- get_compatible_spring_version(spring_boot_version): Get compatible Spring Framework version
- update_dependency_versions(tree, group_id, version): Update dependency versions
- write_xml(pom_file, tree): Write updated XML
- update_pom(pom_file, target_java, target_spring_boot): Main function
"""

import sys
import json
from lxml import etree


def parse_xml(pom_file):
    """
    Parse pom.xml using lxml.
    
    Args:
        pom_file (str): Path to pom.xml file
        
    Returns:
        etree.ElementTree: Parsed XML tree
    """
    parser = etree.XMLParser(remove_blank_text=False)
    tree = etree.parse(pom_file, parser)
    return tree


def update_property(tree, property_name, value):
    """
    Update a property value in the POM.
    
    Args:
        tree (etree.ElementTree): Parsed XML tree
        property_name (str): Name of the property to update
        value (str): New value for the property
    """
    root = tree.getroot()
    namespaces = {'maven': 'http://maven.apache.org/POM/4.0.0'}
    
    # Handle both with and without namespace
    property_xpath = f".//maven:properties/maven:{property_name}"
    property_xpath_no_ns = f".//properties/{property_name}"
    
    property_elem = root.find(property_xpath, namespaces)
    if property_elem is None:
        property_elem = root.find(property_xpath_no_ns)
    
    if property_elem is not None:
        property_elem.text = value
        print(f"✓ Updated property {property_name} to {value}")
    else:
        print(f"⚠ Property {property_name} not found in POM")


def update_parent_version(tree, artifact_id, version):
    """
    Update parent version in the POM.
    
    Args:
        tree (etree.ElementTree): Parsed XML tree
        artifact_id (str): Artifact ID of the parent (e.g., 'spring-boot-starter-parent')
        version (str): New version for the parent
    """
    root = tree.getroot()
    namespaces = {'maven': 'http://maven.apache.org/POM/4.0.0'}
    
    # Handle both with and without namespace
    parent_xpath = ".//maven:parent"
    parent_xpath_no_ns = ".//parent"
    
    parent_elem = root.find(parent_xpath, namespaces)
    if parent_elem is None:
        parent_elem = root.find(parent_xpath_no_ns)
    
    if parent_elem is not None:
        # Find artifactId element
        artifact_elem = parent_elem.find('maven:artifactId', namespaces)
        if artifact_elem is None:
            artifact_elem = parent_elem.find('artifactId')
        
        if artifact_elem is not None and artifact_elem.text == artifact_id:
            # Find version element
            version_elem = parent_elem.find('maven:version', namespaces)
            if version_elem is None:
                version_elem = parent_elem.find('version')
            
            if version_elem is not None:
                version_elem.text = version
                print(f"✓ Updated parent {artifact_id} version to {version}")
            else:
                print(f"⚠ Version element not found in parent")
        else:
            print(f"⚠ Parent artifact ID does not match {artifact_id}")
    else:
        print(f"⚠ Parent element not found in POM")


def get_compatible_spring_version(spring_boot_version):
    """
    Get compatible Spring Framework version for a given Spring Boot version.
    
    Args:
        spring_boot_version (str): Spring Boot version (e.g., '3.0.0')
        
    Returns:
        str: Compatible Spring Framework version
    """
    # Spring Boot 3.x requires Spring Framework 6.x
    if spring_boot_version.startswith('3.'):
        return '6.0.0'
    # Spring Boot 2.7.x uses Spring Framework 5.3.x
    elif spring_boot_version.startswith('2.7'):
        return '5.3.31'
    # Spring Boot 2.6.x and earlier use Spring Framework 5.3.x
    elif spring_boot_version.startswith('2.'):
        return '5.3.31'
    else:
        print(f"⚠ Unknown Spring Boot version {spring_boot_version}, defaulting to Spring Framework 6.0.0")
        return '6.0.0'


def update_dependency_versions(tree, group_id, version):
    """
    Update dependency versions for a specific group ID.
    
    Args:
        tree (etree.ElementTree): Parsed XML tree
        group_id (str): Group ID to match (e.g., 'org.springframework')
        version (str): New version for matching dependencies
    """
    root = tree.getroot()
    namespaces = {'maven': 'http://maven.apache.org/POM/4.0.0'}
    
    # Find all dependencies
    dependencies_xpath = ".//maven:dependencies/maven:dependency"
    dependencies_xpath_no_ns = ".//dependencies/dependency"
    
    dependencies = root.findall(dependencies_xpath, namespaces)
    if not dependencies:
        dependencies = root.findall(dependencies_xpath_no_ns)
    
    updated_count = 0
    for dependency in dependencies:
        # Find groupId element
        group_elem = dependency.find('maven:groupId', namespaces)
        if group_elem is None:
            group_elem = dependency.find('groupId')
        
        if group_elem is not None and group_elem.text == group_id:
            # Find version element
            version_elem = dependency.find('maven:version', namespaces)
            if version_elem is None:
                version_elem = dependency.find('version')
            
            if version_elem is not None:
                artifact_elem = dependency.find('maven:artifactId', namespaces)
                if artifact_elem is None:
                    artifact_elem = dependency.find('artifactId')
                
                artifact_id = artifact_elem.text if artifact_elem is not None else 'unknown'
                version_elem.text = version
                print(f"✓ Updated dependency {group_id}:{artifact_id} to version {version}")
                updated_count += 1
    
    if updated_count == 0:
        print(f"⚠ No dependencies found with groupId {group_id}")


def write_xml(pom_file, tree):
    """
    Write updated XML tree to pom.xml file.
    
    Args:
        pom_file (str): Path to pom.xml file
        tree (etree.ElementTree): XML tree to write
    """
    tree.write(
        pom_file,
        encoding='utf-8',
        xml_declaration=True,
        pretty_print=True
    )
    print(f"✓ Wrote updated POM to {pom_file}")


def update_pom(pom_file, target_java, target_spring_boot=None):
    """
    Main function to update pom.xml with target Java version and Spring Boot version.
    
    Args:
        pom_file (str): Path to pom.xml file
        target_java (str): Target Java version (e.g., '11', '17')
        target_spring_boot (str, optional): Target Spring Boot version (e.g., '3.0.0')
    """
    print(f"📝 Updating {pom_file}...")
    print(f"   Target Java version: {target_java}")
    if target_spring_boot:
        print(f"   Target Spring Boot version: {target_spring_boot}")
    
    # Parse XML
    tree = parse_xml(pom_file)
    
    # Update Java version properties
    update_property(tree, 'java.version', target_java)
    update_property(tree, 'maven.compiler.source', target_java)
    update_property(tree, 'maven.compiler.target', target_java)
    
    # Update Spring Boot if required
    if target_spring_boot:
        update_parent_version(tree, 'spring-boot-starter-parent', target_spring_boot)
        
        # Update Spring Framework dependencies
        spring_framework_version = get_compatible_spring_version(target_spring_boot)
        update_dependency_versions(tree, 'org.springframework', spring_framework_version)
    
    # Write updated XML
    write_xml(pom_file, tree)
    print("✅ POM update complete")


def main():
    """
    Main entry point for the script.
    Reads java_upgrade_recommendation.json and updates pom.xml accordingly.
    """
    if len(sys.argv) < 3:
        print("Usage: python update_pom_versions.py <recommendation_file> <pom_file>")
        sys.exit(1)
    
    recommendation_file = sys.argv[1]
    pom_file = sys.argv[2]
    
    # Read recommendation
    try:
        with open(recommendation_file, 'r') as f:
            recommendation = json.load(f)
    except FileNotFoundError:
        print(f"❌ Recommendation file not found: {recommendation_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in recommendation file: {e}")
        sys.exit(1)
    
    # Extract target versions
    target_java = recommendation.get('target_java_version')
    target_spring_boot = recommendation.get('target_spring_boot_version')
    spring_boot_upgrade_required = recommendation.get('spring_boot_upgrade_required', False)
    
    if not target_java:
        print("❌ No target_java_version found in recommendation")
        sys.exit(1)
    
    # Only update Spring Boot if upgrade is required
    if spring_boot_upgrade_required and target_spring_boot:
        update_pom(pom_file, target_java, target_spring_boot)
    else:
        update_pom(pom_file, target_java)


if __name__ == '__main__':
    main()
