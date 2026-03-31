---
name: release
description: Prepares a new version release by creating a release branch and bumping the version in package.json. Supports patch (default), minor, and major version bumps.
---

# Release Preparation

Automates the release preparation workflow: creates a release branch, bumps the version, and pushes to origin.

## When to Use

- User wants to prepare a new release
- User asks to bump the version
- User wants to create a release branch

## Process

### 1. Parse Arguments

Check if the user specified a bump type:
- `patch` (default) - increments the third number (1.0.1 → 1.0.2)
- `minor` - increments the second number and resets patch (1.0.1 → 1.1.0)
- `major` - increments the first number and resets others (1.0.1 → 2.0.0)

### 2. Read Current Version

Read the `version` field from `package.json` in the project root.

### 3. Calculate New Version

Based on the bump type, calculate the new version number.

### 4. Create Release Branch

Create a new local git branch named `release/v{new-version}`:
```bash
git checkout -b release/v{new-version}
```

### 5. Update package.json

Edit package.json to update the `version` field to the new version.

### 6. Commit the Change

Stage and commit the package.json change:
```bash
git add package.json
git commit -m "chore: bump version to v{new-version}

Co-Authored-By: Claude <noreply@anthropic.com>"
```

### 7. Push to Origin

Push the new branch to the remote:
```bash
git push -u origin release/v{new-version}
```

### 8. Report Success

Display summary:
- Previous version
- New version
- Branch name
- Remote push status
