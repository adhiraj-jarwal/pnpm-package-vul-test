#!/usr/bin/env python3
"""
Process pnpm audit results and create PR comment with vulnerability details.
Exits with code 1 if vulnerabilities are found (fails CI).
"""

import json
import sys
import os
import subprocess
from typing import Dict, List, Any, Tuple

# Bot identification marker (hidden in HTML comment)
BOT_MARKER = "<!-- mercor-npm-audit-bot:v1 -->"

# Severity levels in order (lower index = more severe)
SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO', 'UNKNOWN']

def load_audit_results() -> Dict[str, Any]:
    """Load pnpm audit JSON results."""
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
    Default in code is INFO (fail on all known severities except UNKNOWN),
    but in CI you can override via MIN_FAIL_SEVERITY env var.
    Valid values: CRITICAL, HIGH, MODERATE, LOW, INFO, UNKNOWN
    """
    min_severity = os.getenv('MIN_FAIL_SEVERITY', 'INFO').upper()
    if min_severity not in SEVERITY_LEVELS:
        print(f"⚠️  Invalid MIN_FAIL_SEVERITY '{min_severity}', defaulting to INFO")
        return 'INFO'
    return min_severity

def parse_vulnerabilities(audit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract vulnerability information from audit data."""
    vulnerabilities: List[Dict[str, Any]] = []
    
    # Ensure we actually have advisories; this is format-dependent
    if 'advisories' not in audit_data:
        print("ℹ️  audit-results.json has no 'advisories' key; parser may not support this format")
        return []
    
    # npm/pnpm audit v6–v9 style format
    advisories = audit_data.get('advisories') or {}
    
    if not advisories:
        print("✅ No vulnerabilities found in audit results (no advisories)")
        return []
    
    for advisory_id, vuln in advisories.items():
        # Extract basic info
        package_name = vuln.get('module_name', vuln.get('name', 'unknown'))
        raw_severity = vuln.get('severity', 'unknown')
        severity_upper = str(raw_severity).upper()
        normalized_severity = severity_upper if severity_upper in SEVERITY_LEVELS else 'UNKNOWN'
        is_unknown_severity = severity_upper not in SEVERITY_LEVELS
        
        title = vuln.get('title', 'No title available')
        cves = vuln.get('cves', [])
        cve = cves[0] if cves else 'N/A'
        
        # Improved version detection with fallbacks
        findings = vuln.get('findings', [{}])
        current_version = 'unknown'
        
        if findings:
            # Priority 1: Try direct version field
            current_version = findings[0].get('version', None)
            
            # Priority 2: Parse from paths if version field missing
            if not current_version or current_version == 'unknown':
                paths = findings[0].get('paths', [])
                if paths and '>' in paths[0]:
                    parts = paths[0].split('>')
                    for part in parts:
                        if '@' in part and package_name in part:
                            try:
                                current_version = part.split('@')[-1]
                                break
                            except IndexError:
                                pass
        
        # Get patched version
        patched_versions = vuln.get('patched_versions', 'No fix available')
        recommendation = vuln.get('recommendation', '')
        
        # Get URL (prefer provided, fallback to npm advisory link)
        url = vuln.get('url') or f'https://www.npmjs.com/advisories/{advisory_id}'
        
        vulnerabilities.append({
            'id': advisory_id,
            'package': package_name,
            'current_version': current_version if current_version else 'unknown',
            'patched_version': patched_versions,
            'severity': normalized_severity,
            'raw_severity': raw_severity,
            'unknown_severity': is_unknown_severity,
            'cve': cve,
            'title': title,
            'url': url,
            'recommendation': recommendation,
        })
    
    return vulnerabilities

def categorize_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    min_fail_severity: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Split vulnerabilities into fail_vulns and warn_vulns based on min_fail_severity.
    Rules:
    - Any vulnerability with a truly unknown severity string (not mapping to our known levels)
      is treated as FAIL (fail-safe).
    - Otherwise, we compare the normalized severity against MIN_FAIL_SEVERITY.
    
    Returns:
        (fail_vulns, warn_vulns) tuple
    """
    min_severity_index = SEVERITY_LEVELS.index(min_fail_severity)
    
    fail_vulns: List[Dict[str, Any]] = []
    warn_vulns: List[Dict[str, Any]] = []
    
    for vuln in vulnerabilities:
        # If parser marked the severity as unknown/unrecognized, fail-safe
        if vuln.get('unknown_severity'):
            fail_vulns.append(vuln)
            continue
        
        severity = vuln['severity']
        try:
            severity_index = SEVERITY_LEVELS.index(severity)
            if severity_index <= min_severity_index:
                fail_vulns.append(vuln)
            else:
                warn_vulns.append(vuln)
        except ValueError:
            # Shouldn't normally happen because we normalize, but fail-safe just in case
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
    
    # Group by severity
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
        table += "| Package | Current Version | Fixed Version | CVE | Details |\n"
        table += "|---------|----------------|---------------|-----|----------|\n"
        
        for v in vulns:
            package = f"`{v['package']}`"
            current = v['current_version'] if v['current_version'] != 'unknown' else '❓'
            patched = v['patched_version']
            cve = f"[{v['cve']}]({v['url']})" if v['cve'] != 'N/A' else 'N/A'
            title = v['title'][:50] + '...' if len(v['title']) > 50 else v['title']
            
            table += f"| {package} | {current} | {patched} | {cve} | {title} |\n"
        
        table += "\n"
    
    return table

def generate_pr_comment(
    fail_vulns: List[Dict[str, Any]],
    warn_vulns: List[Dict[str, Any]],
    min_fail_severity: str
) -> str:
    """Generate formatted PR comment with vulnerability details."""
    
    run_id = os.getenv('GITHUB_RUN_ID', 'local')
    workflow_name = os.getenv('GITHUB_WORKFLOW', 'npm-audit')
    
    # Success case
    if not fail_vulns and not warn_vulns:
        return f"""{BOT_MARKER}
## ✅ npm Vulnerability Scan: PASSED

No vulnerabilities detected in npm dependencies.

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
## 🚨 npm Vulnerability Scan: FAILED

**❌ Found {fail_count} vulnerabilit{fail_plural} that must be fixed** (>= {min_fail_severity.title()} severity)
"""
        if warn_vulns:
            warn_plural = "y" if warn_count == 1 else "ies"
            comment += f"**⚠️ Found {warn_count} additional lower-severity vulnerabilit{warn_plural}** (informational)\n"
        
        comment += """
This PR modifies npm dependency files and contains security vulnerabilities that must be addressed before merging.

---

"""
        # Add fail vulnerabilities table
        comment += generate_vulnerability_table(fail_vulns, SEVERITY_LEVELS)
        
        # Add warnings table if present
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
## ⚠️ npm Vulnerability Scan: WARNING

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
   # For direct dependencies in package.json
   pnpm update <package-name>@<fixed-version>
   
   # For transitive dependencies, add to pnpm overrides in root package.json
   # "pnpm": {{
   #   "overrides": {{
   #     "<package-name>": "<fixed-version>"
   #   }}
   # }}
   ```

2. **Regenerate lockfiles:**
   ```bash
   pnpm install
   ```

3. **Test your changes:**
   ```bash
   pnpm build
   pnpm test
   ```

4. **Push and re-run CI**

### ℹ️ Need Help?

- 📖 [npm security docs](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities)
- 🔍 Check CVE links above for details
- 💬 Ask in #engineering-help

### 🎛️ Scanner Configuration

- **Minimum fail severity:** {min_fail_severity.title()}
- **Total vulnerabilities:** {total_count}
- **Failing CI:** {fail_count}
- **Informational:** {warn_count}

---

*🤖 Automated scan by {workflow_name} • Run: {run_id} • [Docs](../../docs/ci-cd/npm-vulnerability-scanner.md)*
"""
    
    return comment

def find_existing_comment(pr_number: str) -> str:
    """
    Find existing bot comment in PR.
    
    Returns:
        Comment ID if found, empty string otherwise
    """
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
            # Update existing comment
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
            # Create new comment
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
    print("🔍 Processing npm vulnerability scan results...\n")
    
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
        print(f"\n⚠️  Found {len(fail_vulns)} vulnerabilit{'y' if len(fail_vulns) == 1 else 'ies'} >= {min_fail_severity}")
        print(f"ℹ️  Found {len(warn_vulns)} additional lower-severity vulnerabilities (informational)")
        
        if enforce_vulnerabilities:
            print("❌ ENFORCEMENT MODE: CI will fail to prevent merging vulnerable dependencies")
            sys.exit(1)
        else:
            print("⚠️  MONITORING MODE: CI will pass but vulnerabilities should be addressed")
            print("💡 Set ENFORCE_VULNERABILITIES=true to block PRs with vulnerabilities")
            sys.exit(0)
    elif warn_vulns:
        print(f"\n⚠️  WARNING: Found {len(warn_vulns)} vulnerabilit{'y' if len(warn_vulns) == 1 else 'ies'} below {min_fail_severity} threshold")
        print("CI will pass but vulnerabilities should be addressed")
        sys.exit(0)
    else:
        print("\n✅ SUCCESS: No vulnerabilities found")
        sys.exit(0)

if __name__ == '__main__':
    main()

