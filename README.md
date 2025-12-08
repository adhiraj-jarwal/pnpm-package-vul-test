# NPM Vulnerability Scanner - Comprehensive Test Suite

Test your vulnerability scanner with **4 realistic scenarios** that demonstrate production security patterns.

---

## 📋 Current Setup (Main Branch)

```bash
Status: VULNERABLE (intentionally for testing)
Package: lodash 4.17.19
Workspaces: app1 (E-commerce) + app2 (Admin)
Known Issues: Prototype Pollution (CVE-2020-8203)
Scanner Config: Fail on CRITICAL, HIGH, MODERATE
```

**This mirrors real-world scenarios where legacy code has vulnerabilities.**

---

## 🧪 Test Scenarios

### **Test 1: Non-Package Change** ✅ (Skip Scan)

**Scenario:** Update documentation, no dependency changes  
**Real-world:** Daily doc updates, README changes, config tweaks

```bash
cd "/Users/adhirajjarwal/Desktop/pnpm package/test-project"
git checkout -b test/docs-update

cat > CHANGELOG.md << 'EOF'
# Changelog

## [1.1.0] - 2024-12-08
### Added
- Improved API documentation
- Enhanced error handling

## [1.0.0] - 2024-12-01
### Initial
- Initial release
EOF

git add CHANGELOG.md
git commit -m "docs: add changelog"
git push -u origin test/docs-update
```

**Expected:**
- ✅ CI PASSES (7-10s)
- 💬 Message: "No npm files changed"
- ⏭️ Scanner SKIPS entirely
- ✅ Merge allowed

---

### **Test 2: "Upgrade" to Still-Vulnerable Version** ❌ (Catches Risk!)

**Scenario:** Developer upgrades lodash 4.17.19 → 4.17.20 (STILL VULNERABLE!)  
**Real-world:** Django 5.1.4 → 5.1.10 when patch requires 5.1.15  
**This is THE most important test** - catches incomplete security fixes!

```bash
cd "/Users/adhirajjarwal/Desktop/pnpm package/test-project"
git checkout main
git checkout -b test/incomplete-security-fix

# Upgrade but not to patched version
sed -i '' 's/"lodash": "4.17.19"/"lodash": "4.17.20"/' apps/web/app1/package.json
sed -i '' 's/"lodash": "4.17.19"/"lodash": "4.17.20"/' apps/web/app2/package.json
sed -i '' 's/"lodash": "4.17.19"/"lodash": "4.17.20"/' package.json

pnpm install
git add -A
git commit -m "chore: upgrade lodash to 4.17.20 (security update)"
git push -u origin test/incomplete-security-fix
```

**Expected:**
- ❌ CI FAILS (30-40s)
- 🤖 Bot posts vulnerability table:
  - **Package:** lodash
  - **Affected:** @test/app1, @test/app2
  - **Current:** 4.17.20
  - **Fixed:** >=4.17.21
  - **CVE:** CVE-2020-8203
  - **Severity:** HIGH
- 🚫 Merge BLOCKED
- **Shows "Affected" column with both workspaces!**

---

### **Test 3: Proper Security Fix** ✅ (Success Path)

**Scenario:** Upgrade to actual patched version lodash 4.17.21  
**Real-world:** Completing the security fix properly

```bash
cd "/Users/adhirajjarwal/Desktop/pnpm package/test-project"
git checkout main
git checkout -b test/security-fix-complete

# Upgrade to patched version
sed -i '' 's/"lodash": "4.17.19"/"lodash": "4.17.21"/' apps/web/app1/package.json
sed -i '' 's/"lodash": "4.17.19"/"lodash": "4.17.21"/' apps/web/app2/package.json
sed -i '' 's/"lodash": "4.17.19"/"lodash": "4.17.21"/' package.json

pnpm install
git add -A
git commit -m "fix: upgrade lodash to 4.17.21 (security patch)"
git push -u origin test/security-fix-complete
```

**Expected:**
- ✅ CI PASSES (30-40s)
- 🤖 Bot posts success message:
  - "✅ npm Vulnerability Scan: PASSED"
  - "No vulnerabilities detected"
- ✅ Merge allowed

---

### **Test 4: Mixed Dependencies** 🎯 (Advanced Scenario)

**Scenario:** Add multiple packages, some safe, some vulnerable  
**Real-world:** New feature adds several dependencies at once

```bash
cd "/Users/adhirajjarwal/Desktop/pnpm package/test-project"
git checkout main
git checkout -b test/mixed-dependencies

# Add to app1: safe axios + vulnerable minimist
cat > apps/web/app1/package.json << 'EOF'
{
  "name": "@test/app1",
  "version": "1.0.0",
  "private": true,
  "description": "Test app 1 - E-commerce frontend",
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "lodash": "4.17.19",
    "axios": "^1.6.0",
    "minimist": "1.2.5"
  }
}
EOF

pnpm install
git add -A
git commit -m "feat: add API client and CLI parser"
git push -u origin test/mixed-dependencies
```

**Expected:**
- ❌ CI FAILS
- 🤖 Bot shows MULTIPLE vulnerabilities:
  - lodash 4.17.19 (Prototype Pollution)
  - minimist 1.2.5 (Prototype Pollution)
- ✅ axios shows as safe (no warning)
- 📊 Demonstrates handling multiple vulnerable packages
- 🚫 Merge BLOCKED

---

## 📊 Expected Results Summary

| Test | Scenario | CI | Bot Comment | File Paths | Merge |
|------|----------|-----|-------------|------------|-------|
| 1 | Docs only | ✅ PASS | "No npm changes" | N/A | ✅ Yes |
| 2 | Upgrade to vulnerable | ❌ FAIL | Vulnerability table | Shows both apps | ❌ No |
| 3 | Upgrade to patched | ✅ PASS | "Scan PASSED" | N/A | ✅ Yes |
| 4 | Mixed packages | ❌ FAIL | Multiple vulns | Shows locations | ❌ No |

---

## 🎯 Why This Test Suite?

### **Test 1: Skip Logic**
- Validates scanner doesn't run on irrelevant changes
- Saves CI time and resources
- Prevents false positives

### **Test 2: The Critical Test** ⭐
- **Most important!** Catches incomplete security fixes
- Real pattern: Developer upgrades but not far enough
- Example: Django 5.1.4 → 5.1.10 (needs 5.1.15)
- Shows your scanner catches this dangerous pattern!

### **Test 3: Success Path**
- Validates scanner passes on secure code
- Shows proper fix workflow
- Demonstrates no false positives

### **Test 4: Complex Scenarios**
- Multiple vulnerable packages
- Mixed safe/unsafe dependencies
- Shows "Affected" column with workspace names
- Demonstrates production-level scanning

---

## ⚙️ Scanner Features Demonstrated

✅ **File Change Detection**
- Triggers on package.json, lockfile changes
- Skips on docs, code, config changes

✅ **Vulnerability Detection**
- Catches all severity levels (CRITICAL, HIGH, MODERATE)
- Multiple CVEs per package
- Multiple vulnerable packages

✅ **Beautiful Reporting**
- Grouped by severity with emojis
- **NEW: "Affected" column shows which workspaces**
- Clickable CVE links
- Fix instructions
- Configuration summary

✅ **Smart Comments**
- Updates existing comments (no spam)
- Hidden bot marker for identification
- Run ID for tracing back to CI logs

✅ **CI Integration**
- Fails on MODERATE+ vulnerabilities
- Passes on clean code
- Blocks dangerous PRs from merging

---

## 🚀 Quick Start

```bash
# Run all 4 tests in sequence
./run-all-tests.sh

# Or run individually as shown above
```

---

## 📖 What Gets Scanned?

The scanner runs when these files change:
- `**/package.json` - Direct dependencies
- `**/pnpm-lock.yaml` - Resolved versions
- `pnpm-workspace.yaml` - Workspace config

Changes to other files skip the scan entirely.

---

## 🔧 Configuration

```yaml
# In .github/workflows/tests.yml
MIN_FAIL_SEVERITY: MODERATE

Fails CI on:
- CRITICAL (🔴)
- HIGH (🟠)
- MODERATE (🟡)

Warns but allows:
- LOW (🔵)
- INFO (ℹ️)
```

---

## 📈 Version Pattern Demonstrated

```
Current:  lodash 4.17.19 (CVE-2020-8203)      ← Vulnerable base
Upgrade:  lodash 4.17.20 (STILL VULNERABLE!)  ← Test 2 catches this!
Required: lodash 4.17.21 (PATCHED)            ← Test 3 validates this
```

**This mirrors Django, Rails, or any framework's security upgrade pattern.**

---

**Ready to test?** Run the scenarios above and watch your scanner in action! 🎉
