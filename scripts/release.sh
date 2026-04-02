#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-patch}"

git fetch origin main
git checkout main
git pull origin main

CURRENT_VERSION=$(node -p "require('./package.json').version")

if [[ "$INPUT" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  NEW_VERSION="$INPUT"
elif [[ "$INPUT" =~ ^(patch|minor|major)$ ]]; then
  NEW_VERSION=$(node -p "
    const [major, minor, patch] = '${CURRENT_VERSION}'.split('.').map(Number);
    if ('${INPUT}' === 'major') \`\${major+1}.0.0\`;
    else if ('${INPUT}' === 'minor') \`\${major}.\${minor+1}.0\`;
    else \`\${major}.\${minor}.\${patch+1}\`;
  ")
else
  echo "Usage: $0 [patch|minor|major|X.Y.Z]"
  exit 1
fi

TAG="v${NEW_VERSION}"
BRANCH="release/${TAG}"

if git ls-remote --tags origin | grep -q "refs/tags/${TAG}$"; then
  echo "Error: Tag $TAG already exists"
  exit 1
fi

git checkout -b "$BRANCH"

node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  pkg.version = '${NEW_VERSION}';
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

git add package.json
git commit -m "chore: bump version to ${TAG}"
git push -u origin "$BRANCH"

gh pr create \
  --title "Release ${TAG}" \
  --body "Bumps version to ${TAG}. Merge to trigger release."

gh pr merge --auto --squash

echo ""
echo "PR created. Once merged, release will build automatically."
