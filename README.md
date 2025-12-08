# NPM Vulnerability Scanner - Test Repository

Test your vulnerability scanner with 3 realistic scenarios before deploying to production.

---

## 📋 Current Setup

```bash
# Main branch has:
- node-forge: 1.3.2 (SAFE - patched version)
- All dependencies secure
- Scanner configured to fail on: CRITICAL, HIGH, MODERATE
```

---

## 🧪 Test Scenarios

### **Test 1: Upgrade to Still-Vulnerable Version** ❌

**Realistic Scenario:** Developer upgrades package but not to the patched version  
**Example:** Django 5.1.10 → 5.1.12 (but patch requires 5.1.15)

```bash
cd "/Users/adhirajjarwal/Desktop/pnpm package/test-project"
git checkout -b test/vulnerable-upgrade

# Downgrade to vulnerable version 1.3.1
sed -i '' 's/"node-forge": "1.3.2"/"node-forge": "1.3.1"/' apps/web/app1/package.json
sed -i '' 's/"node-forge": "1.3.2"/"node-forge": "1.3.1"/' package.json

pnpm install
git add -A
git commit -m "chore: upgrade node-forge to 1.3.1 (still vulnerable)"
git push -u origin test/vulnerable-upgrade
```

**Then:** Create PR on GitHub

**Expected Results:**
- ❌ CI FAILS
- 🤖 Bot posts vulnerability table
- 🚫 Shows node-forge 1.3.1 is vulnerable, needs >=1.3.2
- Merge blocked until fixed

---

### **Test 2: Non-NPM File Change** ✅

**Realistic Scenario:** Update docs/config files, no dependency changes

```bash
git checkout main
git checkout -b test/docs-update

echo "# API Documentation" > API.md
git add API.md
git commit -m "docs: add API documentation"
git push -u origin test/docs-update
```

**Then:** Create PR on GitHub

**Expected Results:**
- ✅ CI PASSES
- 💬 Message: "No npm dependency files changed"
- ⏭️ Scanner skips
- Merge allowed

---

### **Test 3: Proper Security Fix** ✅

**Realistic Scenario:** Upgrade to the actual patched version

```bash
git checkout main
git checkout -b test/security-fix

# Add another safe dependency
npm pkg set dependencies.axios="^1.6.0" --workspace=apps/web/app1
pnpm install
git add -A
git commit -m "fix: add axios (safe version)"
git push -u origin test/security-fix
```

**Then:** Create PR on GitHub

**Expected Results:**
- ✅ CI PASSES
- 🤖 Bot posts "✅ Scan PASSED"
- No vulnerabilities found
- Merge allowed

---

## 📊 Expected Results Summary

| Test | Scenario | CI Status | Bot Comment | Merge |
|------|----------|-----------|-------------|-------|
| 1 | Upgrade to vulnerable version | ❌ FAIL | Vulnerability table | ❌ Blocked |
| 2 | Non-npm change | ✅ PASS | "No npm changes" | ✅ Allowed |
| 3 | Upgrade to patched version | ✅ PASS | "Scan PASSED" | ✅ Allowed |

---

## 🎯 Why This Approach?

**Real-world pattern:**
```
Current:  node-forge 1.3.0 (vulnerable)
Upgrade:  node-forge 1.3.1 (still vulnerable!)  ← Test 1 catches this
Required: node-forge 1.3.2 (patched)           ← Test 3 validates this
```

Nobody intentionally downgrades packages. The real risk is upgrading to a version that's *newer* but still vulnerable.

---

## ⚙️ Scanner Configuration

```yaml
MIN_FAIL_SEVERITY: MODERATE

# Fails CI on:
- CRITICAL
- HIGH  
- MODERATE

# Warns but allows:
- LOW
- INFO
```

---

## 🚀 After Testing

Once all 3 tests pass, deploy to production:

```bash
# Copy scanner to production repo
cp .github/scripts/process-npm-audit.py \
   /path/to/prod-repo/.github/scripts/

# Copy workflow snippet
# See: ../scripts_docs/tests-workflow-snippet.yml
```

---

## 📖 What Gets Checked?

The scanner runs when these files change:
- `**/package.json`
- `**/pnpm-lock.yaml`  
- `pnpm-workspace.yaml`

Changes to other files (docs, code, config) skip the scan entirely.

---

**Ready to test?** Run the 3 scenarios above! 🎉

