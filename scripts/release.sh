#!/usr/bin/env bash
set -euo pipefail

BUMP_TYPE="${1:-patch}"

if [[ ! "$BUMP_TYPE" =~ ^(patch|minor|major)$ ]]; then
  echo "Usage: $0 [patch|minor|major]"
  exit 1
fi

git fetch origin main
git checkout main
git pull origin main

CURRENT_VERSION=$(node -p "require('./package.json').version")
NEW_VERSION=$(node -p "
  const [major, minor, patch] = '${CURRENT_VERSION}'.split('.').map(Number);
  if ('${BUMP_TYPE}' === 'major') console.log(\`\${major+1}.0.0\`);
  else if ('${BUMP_TYPE}' === 'minor') console.log(\`\${major}.\${minor+1}.0\`);
  else console.log(\`\${major}.\${minor}.\${patch+1}\`);
" | tail -1)

BRANCH="release/v${NEW_VERSION}"

git checkout -b "$BRANCH"

node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  pkg.version = '${NEW_VERSION}';
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

git add package.json
git commit -m "chore: bump version to v${NEW_VERSION}"
git push -u origin "$BRANCH"
gh pr create \
  --title "Release v${NEW_VERSION}" \
  --body "Bumps version to v${NEW_VERSION}. Auto-merges after CI passes, then automatically tags and releases."
gh pr merge --auto --squash

echo ""
echo "Release v${NEW_VERSION} initiated."
echo "CI will run, PR will auto-merge, and the release will be published automatically."
