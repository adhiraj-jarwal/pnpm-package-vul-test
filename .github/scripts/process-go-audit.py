#!/usr/bin/env python3
"""
Process Go govulncheck results and create PR comment with vulnerability details.
Exits with code 1 if vulnerabilities are found (fails CI).

Uses govulncheck - official Go vulnerability scanner
"""

import json
import sys
import os
import subprocess
from typing import Dict, List, Any, Tuple

# Bot identification marker (hidden in HTML comment)
BOT_MARKER = "<!-- go-audit-bot:v1 -->"

# Severity levels in order (lower index = more severe)
# Go uses: HIGH, MODERATE, LOW
SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO', 'UNKNOWN']

def load_audit_results() -> Dict[str, Any]:
    """Load govulncheck JSON results (handles NDJSON format)."""
    try:
        with open('go-audit-results.json', 'r') as f:
            content = f.read().strip()
            
            # Handle empty file
            if not content:
                return {'Vulns': []}
            
            # Parse NDJSON format and collect both OSV details and findings
            osvs = {}  # Map of OSV ID to full OSV object
            findings = []
            
            # Split by "}\n{" to separate objects
            # Add back the braces
            objects_text = content.replace('}\n{', '}||SPLIT||{')
            object_strings = objects_text.split('||SPLIT||')
            
            for obj_str in object_strings:
                try:
                    obj = json.loads(obj_str)
                    if not isinstance(obj, dict):
                        continue
                    
                    # Collect OSV vulnerability details
                    if 'osv' in obj and isinstance(obj['osv'], dict):
                        osv_data = obj['osv']
                        osv_id = osv_data.get('id')
                        if osv_id:
                            osvs[osv_id] = osv_data
                    
                    # Collect findings (references to vulnerabilities)
                    if 'finding' in obj:
                        findings.append(obj['finding'])
                except json.JSONDecodeError as e:
                    # Skip invalid JSON objects
                    continue
            
            # Merge findings with their OSV details
            vulns = []
            for finding in findings:
                osv_id = finding.get('osv')
                if osv_id and osv_id in osvs:
                    # Merge finding with OSV details
                    vuln = {
                        **finding,
                        'OSV': osvs[osv_id],
                        'id': osv_id
                    }
                    vulns.append(vuln)
            
            return {'Vulns': vulns}
    except FileNotFoundError:
        print("❌ Error: go-audit-results.json not found")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error loading audit results: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def get_min_fail_severity() -> str:
    """Get minimum severity level that should fail CI."""
    min_severity = os.getenv('MIN_FAIL_SEVERITY', 'MODERATE').upper()
    if min_severity not in SEVERITY_LEVELS:
        print(f"⚠️  Invalid MIN_FAIL_SEVERITY '{min_severity}', defaulting to MODERATE")
        return 'MODERATE'
    return min_severity

def parse_vulnerabilities(audit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract vulnerability information from govulncheck data."""
    vulnerabilities: List[Dict[str, Any]] = []
    
    # govulncheck output format
    vulns = audit_data.get('Vulns', audit_data.get('vulns', []))
    
    if not vulns:
        print("✅ No vulnerabilities found in Go modules")
        return []
    
    print(f"📦 Processing {len(vulns)} vulnerabilities...")
    
    for vuln in vulns:
        # Extract from trace (first element contains the vulnerable module)
        trace = vuln.get('trace', [])
        if not trace:
            continue
            
        first_trace = trace[0]
        module_path = first_trace.get('module', 'unknown')
        current_version = first_trace.get('version', 'unknown')
        
        # Package path is same as module for Go
        package_path = module_path
        
        # Get OSV details
        osv = vuln.get('OSV', {})
        vuln_id = osv.get('id', vuln.get('id', vuln.get('osv', 'UNKNOWN')))
        summary = osv.get('summary', osv.get('details', 'No description available'))
        
        # Get fixed version from finding
        patched_version = vuln.get('fixed_version', 'No fix available')
        
        # Map severity from OSV database_specific or default to MODERATE
        db_specific = osv.get('database_specific', {})
        raw_severity = db_specific.get('severity', 'MODERATE')
        raw_severity = str(raw_severity).upper()
        
        # Normalize severity
        if 'CRITICAL' in raw_severity or 'SEVERE' in raw_severity:
            normalized_severity = 'CRITICAL'
        elif 'HIGH' in raw_severity:
            normalized_severity = 'HIGH'
        elif 'MEDIUM' in raw_severity or 'MODERATE' in raw_severity:
            normalized_severity = 'MODERATE'
        elif 'LOW' in raw_severity:
            normalized_severity = 'LOW'
        else:
            normalized_severity = 'MODERATE'  # Default for Go
        
        # Get URL (prefer Go vulnerability database)
        url = f'https://vuln.go.dev/ID/{vuln_id}'
        
        # Get CVE from aliases
        aliases = osv.get('aliases', [])
        cve = vuln_id  # Default to GO-ID
        for alias in aliases:
            if alias.startswith('CVE-'):
                cve = alias
                break
        
        # Check if vulnerability is called in code (from trace length)
        is_called = len(trace) > 1  # If trace has more than one element, code actually uses it
        
        vulnerabilities.append({
            'module': module_path,
            'package': package_path,
            'current_version': current_version,
            'patched_version': patched_version,
            'severity': normalized_severity,
            'cve': cve,
            'title': summary,
            'url': url,
            'is_called': is_called
        })
    
    return vulnerabilities

def categorize_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    min_fail_severity: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split vulnerabilities into fail_vulns and warn_vulns."""
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
        table += "| Module | Package | Current | Fixed | CVE/ID | Used in Code | Details |\n"
        table += "|--------|---------|---------|-------|--------|--------------|----------|\n"
        
        for v in vulns:
            module = f"`{v['module']}`"
            package = f"`{v['package']}`" if v['package'] != v['module'] else "—"
            current = v['current_version'] if v['current_version'] != 'unknown' else '❓'
            patched = v['patched_version']
            cve = f"[{v['cve']}]({v['url']})" if v['url'] else v['cve']
            is_called = "✅ Yes" if v.get('is_called') else "❌ No"
            title = v['title'][:35] + '...' if len(v['title']) > 35 else v['title']
            
            table += f"| {module} | {package} | {current} | {patched} | {cve} | {is_called} | {title} |\n"
        
        table += "\n"
    
    return table

def generate_pr_comment(
    fail_vulns: List[Dict[str, Any]],
    warn_vulns: List[Dict[str, Any]],
    min_fail_severity: str
) -> str:
    """Generate formatted PR comment with vulnerability details."""
    
    run_id = os.getenv('GITHUB_RUN_ID', 'local')
    workflow_name = os.getenv('GITHUB_WORKFLOW', 'go-audit')
    
    # Success case
    if not fail_vulns and not warn_vulns:
        return f"""{BOT_MARKER}
## ✅ Go Vulnerability Scan: PASSED

No vulnerabilities detected in Go modules.
"""
    
    # Failure / warning case
    total_count = len(fail_vulns) + len(warn_vulns)
    fail_count = len(fail_vulns)
    warn_count = len(warn_vulns)
    
    if fail_vulns:
        fail_plural = "y" if fail_count == 1 else "ies"
        comment = f"""{BOT_MARKER}
## 🚨 Go Vulnerability Scan: FAILED

**❌ Found {fail_count} vulnerabilit{fail_plural} that must be fixed** (>= {min_fail_severity.title()} severity)
"""
        if warn_vulns:
            warn_plural = "y" if warn_count == 1 else "ies"
            comment += f"**⚠️ Found {warn_count} additional lower-severity vulnerabilit{warn_plural}** (informational)\n"
        
        comment += """
This PR modifies Go module files and contains security vulnerabilities that must be addressed before merging.

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
        warn_plural = "y" if warn_count == 1 else "ies"
        comment = f"""{BOT_MARKER}
## ⚠️ Go Vulnerability Scan: WARNING

**Found {warn_count} low-severity vulnerabilit{warn_plural}** (below {min_fail_severity.title()} threshold)

These vulnerabilities don't block CI but should be addressed when possible.

---

"""
        comment += generate_vulnerability_table(warn_vulns, SEVERITY_LEVELS)
    
    # Add fix instructions
    comment += f"""---

### 🔧 How to Fix

**1. Update the vulnerable modules:**

```bash
# Update specific module
go get <module-path>@<fixed-version>

# Or update all modules
go get -u ./...

# Tidy dependencies
go mod tidy
```

**2. Test and push:**

```bash
# Verify fix
govulncheck ./...

# Run tests
go test ./...

# Push changes
git add go.mod go.sum
git commit -m "fix: update vulnerable Go dependencies"
git push
```

### 📊 Scanner Configuration

- **Minimum fail severity:** {min_fail_severity.title()}
- **Total vulnerabilities:** {total_count}
- **Failing CI:** {fail_count}
- **Informational:** {warn_count}
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
    
    try:
        subprocess.run(['gh', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  GitHub CLI (gh) not found - cannot post comment")
        print("Install gh CLI: https://cli.github.com/")
        print("\nComment content:")
        print(comment)
        return
    
    with open('vulnerability-comment.md', 'w') as f:
        f.write(comment)
    
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
    print("🔍 Processing Go vulnerability scan results...\n")
    
    min_fail_severity = get_min_fail_severity()
    enforce_vulnerabilities = os.getenv('ENFORCE_VULNERABILITIES', 'false').lower() == 'true'
    
    print(f"📋 Configuration: MIN_FAIL_SEVERITY = {min_fail_severity}")
    print(f"📋 Configuration: ENFORCE_VULNERABILITIES = {enforce_vulnerabilities}")
    
    audit_data = load_audit_results()
    vulnerabilities = parse_vulnerabilities(audit_data)
    
    fail_vulns, warn_vulns = categorize_vulnerabilities(vulnerabilities, min_fail_severity)
    
    comment = generate_pr_comment(fail_vulns, warn_vulns, min_fail_severity)
    
    post_pr_comment(comment)
    
    if fail_vulns:
        print(f"\n⚠️  Found {len(fail_vulns)} Go vulnerabilit{'y' if len(fail_vulns) == 1 else 'ies'} >= {min_fail_severity}")
        print(f"ℹ️  Found {len(warn_vulns)} additional lower-severity vulnerabilities (informational)")
        
        if enforce_vulnerabilities:
            print("❌ ENFORCEMENT MODE: CI will fail to prevent merging vulnerable dependencies")
            sys.exit(1)
        else:
            print("⚠️  MONITORING MODE: CI will pass but vulnerabilities should be addressed")
            print("💡 Set ENFORCE_VULNERABILITIES=true to block PRs with vulnerabilities")
            sys.exit(0)
    elif warn_vulns:
        print(f"\n⚠️  WARNING: Found {len(warn_vulns)} Go vulnerabilit{'y' if len(warn_vulns) == 1 else 'ies'} below {min_fail_severity} threshold")
        print("CI will pass but vulnerabilities should be addressed")
        sys.exit(0)
    else:
        print("\n✅ SUCCESS: No Go vulnerabilities found")
        sys.exit(0)

if __name__ == '__main__':
    main()

