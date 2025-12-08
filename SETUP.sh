#!/bin/bash

# NPM Vulnerability Scanner - Test Project Setup Script
# This script automates the initial setup of the test project

set -e  # Exit on error

echo "🚀 Setting up NPM Vulnerability Scanner Test Project..."
echo ""

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get current directory
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo -e "${BLUE}📂 Project directory: $PROJECT_DIR${NC}"
echo ""

# Step 1: Check prerequisites
echo -e "${YELLOW}Step 1: Checking prerequisites...${NC}"

if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi
echo "✅ Node.js found: $(node --version)"

if ! command -v pnpm &> /dev/null; then
    echo "⚠️  pnpm not found, installing globally..."
    npm install -g pnpm@9
fi
echo "✅ pnpm found: $(pnpm --version)"

if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi
echo "✅ Git found: $(git --version)"

echo ""

# Step 2: Initialize Git
echo -e "${YELLOW}Step 2: Initializing Git repository...${NC}"

if [ ! -d ".git" ]; then
    git init
    echo "✅ Git repository initialized"
else
    echo "✅ Git repository already exists"
fi

echo ""

# Step 3: Install dependencies
echo -e "${YELLOW}Step 3: Installing npm dependencies...${NC}"
pnpm install
echo "✅ Dependencies installed"
echo ""

# Step 4: Commit initial state
echo -e "${YELLOW}Step 4: Creating initial commit...${NC}"

if [ -z "$(git status --porcelain)" ]; then
    echo "✅ Working directory is clean (already committed)"
else
    git add .
    git commit -m "Initial commit: npm vulnerability scanner test project"
    echo "✅ Initial commit created"
fi

echo ""

# Step 5: Instructions for GitHub setup
echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Create a new GitHub repository (in your test account):"
echo "   https://github.com/new"
echo "   Name: test-npm-vulnerability-scanner"
echo "   Visibility: Public"
echo "   DO NOT initialize with README"
echo ""
echo "2. Add the remote and push (replace YOUR_USERNAME):"
echo ""
echo -e "${YELLOW}   git remote add origin https://github.com/YOUR_USERNAME/test-npm-vulnerability-scanner.git${NC}"
echo -e "${YELLOW}   git branch -M main${NC}"
echo -e "${YELLOW}   git push -u origin main${NC}"
echo ""
echo "3. Start testing! See README.md for test scenarios:"
echo "   - Test 1: Vulnerable package (should fail CI)"
echo "   - Test 2: Non-npm change (should skip scan)"
echo "   - Test 3: Fix vulnerability (should pass CI)"
echo "   - Test 4: Scheduled scan (manual trigger)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}📖 Full instructions: README.md${NC}"
echo ""

