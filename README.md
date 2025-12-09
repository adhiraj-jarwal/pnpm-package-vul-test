# 🔒 GitHub Vulnerabilities Detection

**Multi-language vulnerability scanner for GitHub Actions**

Automatically detect and block vulnerable dependencies in **npm/pnpm**, **Python (pip/uv/poetry)**, and **Go** projects.

**Version**: 2.0.0 | **Updated**: December 9, 2024

---

## 🎯 What This Does

- ✅ **Scans 3 package ecosystems**: npm/pnpm, Python, Go
- ✅ **Posts PR comments** with vulnerability details and fix instructions
- ✅ **Blocks vulnerable PRs** from merging (configurable severity)
- ✅ **Weekly scans** on main branch with GitHub issue alerts
- ✅ **Smart detection** - only runs when dependency files change
- ✅ **Beautiful reports** with severity emojis (🔴🟠🟡🔵ℹ️), CVE links

---

## ⚡ Quick Start (5 minutes)

### 1. Copy Files
```bash
# Navigate to your repo
cd /path/to/your/repository

# Copy workflow
mkdir -p .github/workflows
cp vulnerability-scan.yml .github/workflows/

# Copy scanner scripts
mkdir -p .github/scripts
cp .github/scripts/*.py .github/scripts/
chmod +x .github/scripts/*.py
```

### 2. Test It
```bash
# Create test branch
git checkout -b test/scanner

# Add vulnerable npm package
cd your-app-folder
pnpm add lodash@4.17.19  # or: npm install lodash@4.17.19

# Commit and push
git add package.json *lock.yaml
git commit -m "test: add vulnerable package"
git push -u origin test/scanner

# Create PR
gh pr create --title "Test scanner" --body "Testing"

# Expected: ❌ CI fails, bot posts comment with CVE-2020-8203
```

### 3. Fix It
```bash
# Upgrade to safe version
pnpm update lodash@4.17.21  # or: npm install lodash@4.17.21

git add package.json *lock.yaml
git commit -m "fix: upgrade lodash"
git push

# Expected: ✅ CI passes, bot updates comment
```

---

## 📦 What Gets Scanned

### npm/pnpm Scanner
- **Tool**: `pnpm audit` or `npm audit`
- **Triggers on**: `package.json`, `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`
- **Script**: `.github/scripts/process-npm-audit.py`

### Python Scanner  
- **Tool**: `pip-audit`
- **Triggers on**: `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`
- **Works with**: pip, uv, poetry
- **Script**: `.github/scripts/process-python-audit.py`

### Go Scanner
- **Tool**: `govulncheck` (official Go vulnerability scanner)
- **Triggers on**: `go.mod`, `go.sum`
- **Script**: `.github/scripts/process-go-audit.py`

---

## 🔧 Configuration

### Monitoring vs Enforcement Mode

**DEFAULT: Monitoring Mode** (Production-Safe)

```yaml
env:
  ENFORCE_VULNERABILITIES: false  # Posts comments, NEVER fails CI ✅
```

In **monitoring mode**:
- ✅ Scanner runs and detects vulnerabilities
- ✅ Posts detailed bot comments on PRs
- ✅ **CI always passes** (never blocks merges)
- Use for initial rollout, team training, data collection

**To enable enforcement** (blocks vulnerable PRs):

```yaml
env:
  ENFORCE_VULNERABILITIES: true  # Posts comments AND fails CI ❌
```

In **enforcement mode**:
- Scanner detects vulnerabilities
- Posts bot comments
- **CI fails** if vulnerabilities >= threshold
- Blocks vulnerable PRs from merging

---

### Adjust Severity Threshold

```yaml
env:
  MIN_FAIL_SEVERITY: MODERATE  # Options: CRITICAL, HIGH, MODERATE, LOW, INFO
```

**Recommendations**:
- **Production apps**: `MODERATE` (balanced - current default)
- **Security-critical**: `LOW` (strict)
- **Internal tools**: `HIGH` (lenient)

**Note**: Only matters in enforcement mode. In monitoring mode, all vulnerabilities are reported but never fail CI.

### Change Scan Schedule

```yaml
schedule:
  # Current: Weekly Monday 3 AM UTC
  - cron: '0 3 * * 1'
  
  # Daily at 3 AM UTC
  - cron: '0 3 * * *'
  
  # Bi-weekly (1st and 15th)
  - cron: '0 3 1,15 * *'
```

### Disable Unused Scanners

Comment out scanners you don't need:

```yaml
jobs:
  scan-npm-vulnerabilities:
    # Keep this
    
  # scan-python-vulnerabilities:
  #   # Disabled - no Python in this project
    
  # scan-go-vulnerabilities:
  #   # Disabled - no Go in this project
```

### Update Tool Versions

```yaml
# Node.js version
- uses: actions/setup-node@v4
  with:
    node-version: '20'  # Change to: 18, 20, 22

# Python version
- uses: actions/setup-python@v5
  with:
    python-version: '3.11'  # Change to: 3.9, 3.10, 3.11, 3.12

# Go version
- uses: actions/setup-go@v5
  with:
    go-version: '1.21'  # Change to: 1.20, 1.21, 1.22
```

---

## 🧪 Testing Scenarios

### Test 1: Skip Scan (Non-Dependency Change)
```bash
# Make a documentation change
echo "# Test" >> README.md
git add README.md
git commit -m "docs: test"
git push

# Expected: ✅ Scanner skips (no dependency files changed)
```

### Test 2: npm - Vulnerable Package
```bash
# Add vulnerable lodash
pnpm add lodash@4.17.19

git add package.json pnpm-lock.yaml
git commit -m "test: vulnerable lodash"
git push

# Expected: ❌ CI fails, bot shows CVE-2020-8203
```

### Test 3: npm - Incomplete Fix
```bash
# Upgrade but not enough
pnpm update lodash@4.17.20  # Still vulnerable!

git add package.json pnpm-lock.yaml
git commit -m "chore: upgrade lodash"
git push

# Expected: ❌ Still fails - proves scanner catches incomplete fixes
```

### Test 4: npm - Complete Fix
```bash
# Upgrade to patched version
pnpm update lodash@4.17.21

git add package.json pnpm-lock.yaml
git commit -m "fix: upgrade to patched lodash"
git push

# Expected: ✅ CI passes, bot shows success
```

### Test 5: Python - Vulnerable Package
```bash
# Create requirements.txt with vulnerable package
echo "django==2.2.0" > requirements.txt

git add requirements.txt
git commit -m "test: vulnerable django"
git push

# Expected: ❌ CI fails with Django vulnerabilities
```

### Test 6: Go - Vulnerable Module
```bash
# Create go.mod with vulnerable package
cat > go.mod << 'EOF'
module github.com/test/app

go 1.21

require golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2
EOF

go mod tidy

git add go.mod go.sum
git commit -m "test: vulnerable go crypto"
git push

# Expected: ❌ CI fails with Go vulnerability
```

### Test 7: Scheduled Scan (Manual Trigger)
```bash
# Trigger weekly scan manually
gh workflow run vulnerability-scan.yml

# Wait 2-3 minutes, then check
gh issue list --label "security,vulnerabilities"

# Expected: Issue created if vulnerabilities found
```

---

## 📊 Sample Output

### PR Comment Example
```markdown
## 🚨 npm Vulnerability Scan: FAILED

**❌ Found 1 vulnerability that must be fixed** (>= Moderate severity)

---

### 🟠 High Severity (1)

| Package | Current | Fixed | CVE | Details |
|---------|---------|-------|-----|---------|
| `lodash` | 4.17.19 | >=4.17.21 | CVE-2020-8203 | Prototype Pollution |

---

### 🔧 How to Fix

1. Update the vulnerable package:
   ```bash
   pnpm update lodash@4.17.21
   ```

2. Regenerate lockfiles:
   ```bash
   pnpm install
   ```

3. Test your changes:
   ```bash
   pnpm build && pnpm test
   ```

4. Push and re-run CI
```

### GitHub Issue Example (Weekly Scan)
```markdown
## 🚨 Weekly Vulnerability Scan: Issues Detected

Found **2** total vulnerabilities across all package managers.

### 📊 Summary
- 📦 npm/pnpm: 2 vulnerabilities
- 🐍 Python: 0 vulnerabilities
- 🔷 Go: 0 vulnerabilities

### 🔧 Next Steps
1. Review vulnerabilities in workflow logs
2. Create PRs to upgrade packages
3. Close this issue once resolved
```

---

## 🎨 Severity Levels

| Icon | Level | CI Behavior (default) |
|------|-------|-----------------------|
| 🔴 | CRITICAL | Fails CI ❌ |
| 🟠 | HIGH | Fails CI ❌ |
| 🟡 | MODERATE | Fails CI ❌ |
| 🔵 | LOW | Passes (warning) ✅ |
| ℹ️ | INFO | Passes (warning) ✅ |

---

## 📁 Project Structure

```
your-repo/
├── .github/
│   ├── workflows/
│   │   └── vulnerability-scan.yml    # Main workflow
│   └── scripts/
│       ├── process-npm-audit.py      # npm/pnpm scanner
│       ├── process-python-audit.py   # Python scanner
│       └── process-go-audit.py       # Go scanner
│
└── README.md                         # This file
```

---

## 🚨 Troubleshooting

### Scanner Not Running?
**Check if dependency files changed**:
```bash
git diff origin/main...HEAD -- '**/package.json' '**/requirements.txt' '**/go.mod'
```

### Bot Not Commenting?
**Verify permissions** in workflow file:
```yaml
permissions:
  pull-requests: write  # Required!
```

**Check PR number is set**:
```bash
gh pr view --json number
```

### Too Many Failures?
**Adjust severity threshold** to be less strict:
```yaml
MIN_FAIL_SEVERITY: HIGH  # Only fail on HIGH and CRITICAL
```

### Scan Takes Too Long?
**Disable unused scanners** - Comment out jobs you don't use

**Add caching**:
```yaml
- uses: actions/cache@v4
  with:
    path: ~/.pnpm-store
    key: ${{ runner.os }}-pnpm-${{ hashFiles('**/pnpm-lock.yaml') }}
```

### False Positives?
**Ignore specific vulnerabilities**:

For npm/pnpm, add to `package.json`:
```json
{
  "pnpm": {
    "overrides": {
      "vulnerable-package": "safe-version"
    }
  }
}
```

For Python:
```bash
pip-audit --ignore-vuln CVE-XXXX-XXXXX
```

For Go:
```go
// In go.mod
replace vulnerable.com/package => safe.com/package v1.0.0
```

---

## 🔍 How It Works

### On Pull Requests
1. **Detects changes** in dependency files
2. **Skips if no changes** (saves CI time)
3. **Runs appropriate scanner** (npm/Python/Go)
4. **Posts/updates PR comment** with results
5. **Fails CI** if vulnerabilities >= threshold

### On Schedule (Weekly)
1. **Runs Monday 3 AM UTC** on main branch
2. **Scans all three** package managers
3. **Creates GitHub issue** if vulnerabilities found
4. **Uploads results** as artifacts (30-day retention)

---

## ⚙️ Advanced Configuration

### Different Thresholds per Scanner
```yaml
# Strict for npm
scan-npm-vulnerabilities:
  env:
    MIN_FAIL_SEVERITY: LOW

# Moderate for Python
scan-python-vulnerabilities:
  env:
    MIN_FAIL_SEVERITY: MODERATE

# Lenient for Go
scan-go-vulnerabilities:
  env:
    MIN_FAIL_SEVERITY: HIGH
```

### Custom File Patterns
```yaml
- name: Check for npm changes
  uses: tj-actions/changed-files@v46
  with:
    files: |
      **/package.json
      **/pnpm-lock.yaml
      **/.npmrc           # Add custom patterns
```

### Add Team Mentions
Edit scanner scripts (`generate_pr_comment()` function):
```python
comment = f"""{BOT_MARKER}
## 🚨 npm Vulnerability Scan: FAILED

@security-team please review

**❌ Found {fail_count} vulnerabilities**
"""
```

---

## 📈 Best Practices

### For Development Teams
1. ✅ Address alerts within 48 hours
2. ✅ Keep dependencies updated regularly
3. ✅ Test fixes thoroughly before merging
4. ✅ Use Dependabot for automatic updates

### For Security Teams
1. ✅ Start with MODERATE threshold, adjust based on feedback
2. ✅ Monitor trends over time
3. ✅ Review scheduled scan results weekly
4. ✅ Document accepted exceptions

### For Platform Teams
1. ✅ Update scanner tools quarterly
2. ✅ Cache dependencies for faster CI
3. ✅ Provide team training (15-min overview)
4. ✅ Track metrics (scan duration, fix time)

---

## 📊 Changelog

### Version 2.0.0 (December 9, 2024)
- ✨ Added multi-language support (npm, Python, Go)
- ✨ Added scheduled weekly scans
- ✨ Added GitHub issue creation
- ✨ Parallel scanner execution
- ✨ Smart change detection
- 📝 Comprehensive documentation
- 🔧 Configurable severity thresholds

### Version 1.0.0 (December 1, 2024)
- 🎉 Initial release with npm scanning only

---

## 🤝 Contributing

Improvements welcome! Areas to enhance:
- Additional package managers (Rust, Ruby, etc.)
- Custom severity rules per package
- Integration with other security tools
- Better severity normalization

---

## 📚 Resources

### Tools Used
- [pnpm audit](https://pnpm.io/cli/audit) - npm/pnpm vulnerability scanning
- [npm audit](https://docs.npmjs.com/cli/audit) - npm vulnerability scanning
- [pip-audit](https://github.com/pypa/pip-audit) - Python vulnerability scanning
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Go vulnerability scanning
- [GitHub Actions](https://docs.github.com/en/actions) - CI/CD automation
- [GitHub CLI](https://cli.github.com/) - Comment and issue management

### Security Resources
- [National Vulnerability Database](https://nvd.nist.gov/)
- [npm Security Advisories](https://www.npmjs.com/advisories)
- [Python Security](https://python.org/dev/security/)
- [Go Vulnerability Database](https://vuln.go.dev/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## ✅ Deployment Checklist

- [ ] Copy workflow file to `.github/workflows/`
- [ ] Copy scanner scripts to `.github/scripts/`
- [ ] Make scripts executable (`chmod +x`)
- [ ] Configure Node.js/Python/Go versions
- [ ] Set severity thresholds
- [ ] Disable unused scanners (optional)
- [ ] Push to GitHub
- [ ] Test with vulnerable package PR
- [ ] Verify bot comments work
- [ ] Test scheduled scan (manual trigger)
- [ ] Train team on responding to alerts

---

## 🎉 Summary

You now have a production-ready vulnerability scanner that:
- ✅ Scans npm/pnpm, Python (pip/uv/poetry), and Go
- ✅ Posts detailed PR comments with fix instructions
- ✅ Blocks vulnerable code from merging
- ✅ Monitors main branch weekly
- ✅ Creates GitHub issues for security alerts
- ✅ Saves CI time with smart change detection

---

## 📞 Quick Reference

```bash
# Deploy
cp vulnerability-scan.yml .github/workflows/
cp .github/scripts/*.py .github/scripts/
chmod +x .github/scripts/*.py

# Test locally
pnpm audit --json          # npm/pnpm
pip-audit --format json    # Python
govulncheck -json ./...    # Go

# Trigger manually
gh workflow run vulnerability-scan.yml

# View results
gh run list --workflow=vulnerability-scan.yml
gh pr view <number> --comments
gh issue list --label "security"
```

---

**Project**: GitHub Vulnerabilities Detection  
**Version**: 2.0.0  
**License**: Open Source  
**Created**: December 9, 2024

*Built with ❤️ for secure software development*
