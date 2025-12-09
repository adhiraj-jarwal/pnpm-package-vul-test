#!/usr/bin/env python3
"""
Process Python pip-audit results and create PR comment with vulnerability details.
Exits with code 1 if vulnerabilities are found (fails CI).

Supports: pip-audit, safety, and uv-based projects
"""

import json
import sys
import os
import subprocess
from typing import Dict, List, Any, Tuple

# Bot identification marker (hidden in HTML comment)
BOT_MARKER = "<!-- python-audit-bot:v1 -->"

# Severity levels in order (lower index = more severe)
SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO', 'UNKNOWN']

def load_audit_results() -> Dict[str, Any]:
    """Load pip-audit JSON results."""
    try:
        with open('audit-results.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ Error: audit-results.json not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing audit results: {e}")
        sys.exit(1)

def get_min_fail_severity() -> str:
    """
    Get minimum severity level that should fail CI.
    Default is MODERATE, can override via MIN_FAIL_SEVERITY env var.
    """
    min_severity = os.getenv('MIN_FAIL_SEVERITY', 'MODERATE').upper()
    if min_severity not in SEVERITY_LEVELS:
        print(f"⚠️  Invalid MIN_FAIL_SEVERITY '{min_severity}', defaulting to MODERATE")
        return 'MODERATE'
    return min_severity

def parse_vulnerabilities(audit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract vulnerability information from pip-audit data."""
    vulnerabilities: List[Dict[str, Any]] = []
    
    # pip-audit format: list of vulnerabilities
    vulns_list = audit_data.get('vulnerabilities', audit_data.get('dependencies', []))
    
    if not vulns_list:
        print("✅ No vulnerabilities found in audit results")
        return []
    
    for vuln_entry in vulns_list:
        # Handle different formats
        if isinstance(vuln_entry, dict):
            # pip-audit format
            package_name = vuln_entry.get('name', 'unknown')
            current_version = vuln_entry.get('version', 'unknown')
            
            # Get vulnerabilities for this package
            vulns = vuln_entry.get('vulns', [vuln_entry])
            
            for vuln in vulns:
                # Extract vulnerability details
                vuln_id = vuln.get('id', vuln.get('cve', 'UNKNOWN'))
                
                # Map severity
                raw_severity = str(vuln.get('severity', vuln.get('advisory', {}).get('severity', 'UNKNOWN'))).upper()
                # pip-audit uses: LOW, MODERATE, HIGH, CRITICAL
                normalized_severity = raw_severity if raw_severity in SEVERITY_LEVELS else 'UNKNOWN'
                
                title = vuln.get('description', vuln.get('summary', 'No description available'))
                
                # Get fixed versions
                fixed_versions = vuln.get('fix_versions', vuln.get('fixed_in', []))
                if isinstance(fixed_versions, list) and fixed_versions:
                    patched_version = f">={fixed_versions[0]}"
                elif isinstance(fixed_versions, str):
                    patched_version = fixed_versions
                else:
                    patched_version = "No fix available"
                
                # Get URL
                url = vuln.get('url', vuln.get('link', f'https://pypi.org/project/{package_name}/'))
                
                # Get affected location (requirements file, pyproject.toml, etc.)
                affected_paths = []
                if 'file' in vuln_entry:
                    affected_paths.append(vuln_entry['file'])
                elif os.path.exists('requirements.txt'):
                    affected_paths.append('requirements.txt')
                elif os.path.exists('pyproject.toml'):
                    affected_paths.append('pyproject.toml')
                
                vulnerabilities.append({
                    'package': package_name,
                    'current_version': current_version,
                    'patched_version': patched_version,
                    'severity': normalized_severity,
                    'cve': vuln_id,
                    'title': title,
                    'url': url,
                    'affected_paths': affected_paths,
                })
    
    return vulnerabilities

def categorize_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    min_fail_severity: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split vulnerabilities into fail_vulns and warn_vulns based on min_fail_severity."""
    min_severity_index = SEVERITY_LEVELS.index(min_fail_severity)
    
    fail_vulns: List[Dict[str, Any]] = []
    warn_vulns: List[Dict[str, Any]] = []
    
    for vuln in vulnerabilities:
        severity = vuln['severity']
        try:
            severity_index = SEVERITY_LEVELS.index(severity)
            if severity_index <= min_severity_index:
                fail_vulns.append(vuln)
            else:
                warn_vulns.append(vuln)
        except ValueError:
            # Unknown severity - fail-safe
            fail_vulns.append(vuln)
    
    return fail_vulns, warn_vulns

def get_severity_emoji(severity: str) -> str:
    """Get emoji for severity level."""
    severity_map = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MODERATE': '🟡',
        'LOW': '🔵',
        'INFO': 'ℹ️',
        'UNKNOWN': '⚪'
    }
    return severity_map.get(severity.upper(), '⚪')

def generate_vulnerability_table(
    vulnerabilities: List[Dict[str, Any]],
    severity_order: List[str]
) -> str:
    """Generate markdown table for vulnerabilities grouped by severity."""
    if not vulnerabilities:
        return ""
    
    grouped: Dict[str, List[Dict[str, Any]]] = {severity: [] for severity in severity_order}
    grouped.setdefault('UNKNOWN', [])
    
    for v in vulnerabilities:
        severity = v['severity'].upper()
        if severity not in grouped:
            severity = 'UNKNOWN'
        grouped[severity].append(v)
    
    table = ""
    for severity in severity_order:
        vulns = grouped.get(severity, [])
        if not vulns:
            continue
        
        emoji = get_severity_emoji(severity)
        table += f"### {emoji} {severity.title()} Severity ({len(vulns)})\n\n"
        table += "| Package | Affected | Current | Fixed | CVE/ID | Details |\n"
        table += "|---------|----------|---------|-------|--------|----------|\n"
        
        for v in vulns:
            package = f"`{v['package']}`"
            
            # Format affected paths
            paths = v.get('affected_paths', [])
            if paths:
                affected = ', '.join(f"`{p}`" for p in paths[:2])
                if len(paths) > 2:
                    affected += f" (+{len(paths)-2} more)"
            else:
                affected = "—"
            
            current = v['current_version'] if v['current_version'] != 'unknown' else '❓'
            patched = v['patched_version']
            cve = f"[{v['cve']}]({v['url']})" if v['url'] else v['cve']
            title = v['title'][:40] + '...' if len(v['title']) > 40 else v['title']
            
            table += f"| {package} | {affected} | {current} | {patched} | {cve} | {title} |\n"
        
        table += "\n"
    
    return table

def generate_pr_comment(
    fail_vulns: List[Dict[str, Any]],
    warn_vulns: List[Dict[str, Any]],
    min_fail_severity: str
) -> str:
    """Generate formatted PR comment with vulnerability details."""
    
    run_id = os.getenv('GITHUB_RUN_ID', 'local')
    workflow_name = os.getenv('GITHUB_WORKFLOW', 'python-audit')
    
    # Success case
    if not fail_vulns and not warn_vulns:
        return f"""{BOT_MARKER}
## ✅ Python Vulnerability Scan: PASSED

No vulnerabilities detected in Python dependencies.

---
*🤖 Automated scan by {workflow_name} • Run: {run_id}*
"""
    
    # Failure / warning case
    total_count = len(fail_vulns) + len(warn_vulns)
    fail_count = len(fail_vulns)
    warn_count = len(warn_vulns)
    
    if fail_vulns:
        fail_plural = "y" if fail_count == 1 else "ies"
        comment = f"""{BOT_MARKER}
## 🚨 Python Vulnerability Scan: FAILED

**❌ Found {fail_count} vulnerabilit{fail_plural} that must be fixed** (>= {min_fail_severity.title()} severity)
"""
        if warn_vulns:
            warn_plural = "y" if warn_count == 1 else "ies"
            comment += f"**⚠️ Found {warn_count} additional lower-severity vulnerabilit{warn_plural}** (informational)\n"
        
        comment += """
This PR modifies Python dependency files and contains security vulnerabilities that must be addressed before merging.

---

"""
        comment += generate_vulnerability_table(fail_vulns, SEVERITY_LEVELS)
        
        if warn_vulns:
            comment += """---

### ℹ️ Lower Severity Vulnerabilities (Informational)

These vulnerabilities are below the fail threshold but should be addressed when possible.

"""
            comment += generate_vulnerability_table(warn_vulns, SEVERITY_LEVELS)
    
    else:
        # Only warnings, no failures
        warn_plural = "y" if warn_count == 1 else "ies"
        comment = f"""{BOT_MARKER}
## ⚠️ Python Vulnerability Scan: WARNING

**Found {warn_count} low-severity vulnerabilit{warn_plural}** (below {min_fail_severity.title()} threshold)

These vulnerabilities don't block CI but should be addressed when possible.

---

"""
        comment += generate_vulnerability_table(warn_vulns, SEVERITY_LEVELS)
    
    # Add fix instructions
    comment += f"""---

### 🔧 How to Fix

1. **Update the vulnerable packages:**
   ```bash
   # For pip
   pip install --upgrade <package-name>==<fixed-version>
   
   # For uv
   uv pip install --upgrade <package-name>==<fixed-version>
   
   # For poetry
   poetry update <package-name>
   ```

2. **Regenerate lockfiles:**
   ```bash
   # For pip
   pip freeze > requirements.txt
   
   # For uv
   uv pip freeze > requirements.txt
   
   # For poetry
   poetry lock
   ```

3. **Test your changes:**
   ```bash
   python -m pytest
   # or your test command
   ```

4. **Push and re-run CI**

### ℹ️ Need Help?

- 📖 [Python security docs](https://python.org/dev/security/)
- 🔍 Check CVE links above for details
- 💬 Ask in #engineering-help

### 🎛️ Scanner Configuration

- **Minimum fail severity:** {min_fail_severity.title()}
- **Total vulnerabilities:** {total_count}
- **Failing CI:** {fail_count}
- **Informational:** {warn_count}

---

*🤖 Automated scan by {workflow_name} • Run: {run_id}*
"""
    
    return comment

def find_existing_comment(pr_number: str) -> str:
    """Find existing bot comment in PR."""
    try:
        result = subprocess.run(
            [
                'gh',
                'api',
                f'repos/{{owner}}/{{repo}}/issues/{pr_number}/comments',
                '--jq',
                f'.[] | select(.body | contains("{BOT_MARKER}")) | .id'
            ],
            capture_output=True,
            text=True,
            check=True
        )
        comment_id = result.stdout.strip()
        return comment_id if comment_id else ""
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""

def post_pr_comment(comment: str):
    """Post or update comment on PR using GitHub CLI."""
    pr_number = os.getenv('PR_NUMBER')
    
    if not pr_number:
        print("ℹ️  Not in PR context - skipping comment posting")
        print("\n" + "=" * 80)
        print("GENERATED COMMENT (would be posted to PR):")
        print("=" * 80)
        print(comment)
        print("=" * 80)
        return
    
    # Check if gh CLI is available
    try:
        subprocess.run(['gh', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  GitHub CLI (gh) not found - cannot post comment")
        print("Install gh CLI: https://cli.github.com/")
        print("\nComment content:")
        print(comment)
        return
    
    # Write comment to file
    with open('vulnerability-comment.md', 'w') as f:
        f.write(comment)
    
    # Try to find and update existing comment
    existing_comment_id = find_existing_comment(pr_number)
    
    try:
        if existing_comment_id:
            subprocess.run(
                [
                    'gh',
                    'api',
                    f'repos/{{owner}}/{{repo}}/issues/comments/{existing_comment_id}',
                    '-X', 'PATCH',
                    '-F', 'body=@vulnerability-comment.md'
                ],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"✅ Updated existing comment on PR #{pr_number}")
        else:
            subprocess.run(
                ['gh', 'pr', 'comment', pr_number, '--body-file', 'vulnerability-comment.md'],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"✅ Posted new comment to PR #{pr_number}")
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Failed to post/update PR comment: {e.stderr}")
        print("Comment content:")
        print(comment)

def main():
    """Main execution function."""
    print("🔍 Processing Python vulnerability scan results...\n")
    
    # Load configuration
    min_fail_severity = get_min_fail_severity()
    enforce_vulnerabilities = os.getenv('ENFORCE_VULNERABILITIES', 'false').lower() == 'true'
    
    print(f"📋 Configuration: MIN_FAIL_SEVERITY = {min_fail_severity}")
    print(f"📋 Configuration: ENFORCE_VULNERABILITIES = {enforce_vulnerabilities}")
    
    # Load and parse results
    audit_data = load_audit_results()
    vulnerabilities = parse_vulnerabilities(audit_data)
    
    # Categorize vulnerabilities
    fail_vulns, warn_vulns = categorize_vulnerabilities(vulnerabilities, min_fail_severity)
    
    # Generate comment
    comment = generate_pr_comment(fail_vulns, warn_vulns, min_fail_severity)
    
    # Post comment to PR
    post_pr_comment(comment)
    
    # Exit with appropriate code
    if fail_vulns:
        print(f"\n⚠️  Found {len(fail_vulns)} Python vulnerabilit{'y' if len(fail_vulns) == 1 else 'ies'} >= {min_fail_severity}")
        print(f"ℹ️  Found {len(warn_vulns)} additional lower-severity vulnerabilities (informational)")
        
        if enforce_vulnerabilities:
            print("❌ ENFORCEMENT MODE: CI will fail to prevent merging vulnerable dependencies")
            sys.exit(1)
        else:
            print("⚠️  MONITORING MODE: CI will pass but vulnerabilities should be addressed")
            print("💡 Set ENFORCE_VULNERABILITIES=true to block PRs with vulnerabilities")
            sys.exit(0)
    elif warn_vulns:
        print(f"\n⚠️  WARNING: Found {len(warn_vulns)} Python vulnerabilit{'y' if len(warn_vulns) == 1 else 'ies'} below {min_fail_severity} threshold")
        print("CI will pass but vulnerabilities should be addressed")
        sys.exit(0)
    else:
        print("\n✅ SUCCESS: No Python vulnerabilities found")
        sys.exit(0)

if __name__ == '__main__':
    main()

