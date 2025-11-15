import yaml
import re
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def parse_yara_rule(file_path):
    """Extract basic info from YARA rule file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        rules = []
        pattern = r'rule\s+(\w+)\s*(?::\s*([\w\s]+))?\s*\{(.*?)^\}'

        for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
            rule_name = match.group(1)
            tags = match.group(2).split() if match.group(2) else []

            rules.append({
                'name': rule_name,
                'file': os.path.relpath(file_path)
            })

        return rules
    except Exception as e:
        print(f"Error parsing YARA {file_path}: {e}")
        return []

def parse_sigma_rule(file_path):
    """Extract basic info from Sigma rule file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            rule = yaml.safe_load(f)

        if not rule or not isinstance(rule, dict) or 'detection' not in rule:
            return None

        return {
            'title': rule.get('title', 'N/A'),
            'level': rule.get('level', 'medium'),
            'file': os.path.relpath(file_path)
        }
    except Exception as e:
        return None

def generate_index(yara_rules, sigma_rules, output_file='RULES_INDEX.md'):
    """Generate simple index markdown"""

    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("# Detection Rules Index\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

        # Quick stats
        f.write(f"**Total Rules:** {len(yara_rules) + len(sigma_rules)} ")
        f.write(f"({len(yara_rules)} YARA, {len(sigma_rules)} Sigma)\n\n")

        f.write("---\n\n")

        # YARA Rules Index
        f.write("## YARA Rules\n\n")

        if yara_rules:
            f.write("| # | Rule Name | File |\n")
            f.write("|---|-----------|------|\n")

            for idx, rule in enumerate(sorted(yara_rules, key=lambda x: x['name']), 1):
                f.write(f"| {idx} | `{rule['name']}` | `{rule['file']}` |\n")
        else:
            f.write("*No YARA rules found.*\n")

        f.write("\n---\n\n")

        # Sigma Rules Index
        f.write("## Sigma Rules\n\n")

        if sigma_rules:
            # Group by severity for cleaner index
            by_level = defaultdict(list)
            for rule in sigma_rules:
                by_level[rule['level']].append(rule)

            # Order by severity
            for level in ['critical', 'high', 'medium', 'low', 'informational']:
                if level not in by_level:
                    continue

                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                        'low': '🟢', 'informational': '🔵'}.get(level, '⚪')

                f.write(f"### {emoji} {level.upper()}\n\n")
                f.write("| # | Title | File |\n")
                f.write("|---|-------|------|\n")

                idx = 1
                for rule in sorted(by_level[level], key=lambda x: x['title']):
                    f.write(f"| {idx} | {rule['title']} | `{rule['file']}` |\n")
                    idx += 1

                f.write("\n")
        else:
            f.write("*No Sigma rules found.*\n")

        f.write("\n---\n\n")

def main():
    """Main execution"""
    print("Scanning for detection rules...")

    # Find YARA files
    yara_files = list(Path('.').rglob('*.yar')) + list(Path('.').rglob('*.yara'))

    # Find Sigma files
    sigma_files = []
    for yml_file in Path('.').rglob('*.yml'):
        try:
            with open(yml_file, 'r') as f:
                content = yaml.safe_load(f)
                if isinstance(content, dict) and 'detection' in content:
                    sigma_files.append(yml_file)
        except:
            pass

    print(f"  Found {len(yara_files)} YARA files")
    print(f"  Found {len(sigma_files)} Sigma files")

    # Parse rules
    yara_rules = []
    for file in yara_files:
        rules = parse_yara_rule(file)
        yara_rules.extend(rules)

    sigma_rules = []
    for file in sigma_files:
        rule = parse_sigma_rule(file)
        if rule:
            sigma_rules.append(rule)

    print(f"\n Parsed {len(yara_rules)} YARA rules")
    print(f" Parsed {len(sigma_rules)} Sigma rules")

    # Generate index
    generate_index(yara_rules, sigma_rules)

if __name__ == "__main__":
    main()