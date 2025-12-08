# Documentation

This is a test file to verify the vulnerability scanner skips when no npm files are modified.

## Purpose

The scanner should only run when:
- package.json files change
- pnpm-lock.yaml changes
- pnpm-workspace.yaml changes

This file change should NOT trigger the vulnerability scan.

