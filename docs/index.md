# Security Review Tool

A CLI tool for performing security reviews on AWS CDK and CloudFormation projects. It scans CloudFormation templates and CDK constructs for security issues, generates data flow diagrams and threat models, and produces detailed assessment reports. Built with TypeScript, Commander.js, and Amazon Bedrock.

For end-user documentation (installation, CLI usage, CI/CD integration), see [docs/USER-GUIDE.md](docs/USER-GUIDE.md). For architecture patterns and code conventions, see [.claude/CLAUDE.md](.claude/CLAUDE.md).

## Prerequisites

- [Node.js](https://nodejs.org/) 22+
- [Git](https://git-scm.com/downloads)
- [Bun](https://bun.sh/) (required for CLI binary compilation)
- AWS credentials with `bedrock:InvokeModel` permission (env vars, SSO, named profiles, or federated roles)
- (Optional) [mise](https://mise.jdx.dev/getting-started.html) — manages tool versions and runs tasks via `mise.toml`

## Getting Started

### Clone and Install

```bash
git clone <repo-url>
cd security-review-tool
npm ci
```

### Build and Verify

```bash
npm run build    # TypeScript compilation
npm test         # Run tests
```

## Project Structure

```
src/                        # Application source
  index.ts                  # CLI entry point (Commander.js)
  assess/                   # Assess command
  config/                   # Config command
  fix/                      # Fix command
  status/                   # Status command
  update/                   # Update command
  shared/                   # Cross-cutting utilities (AI, auth, etc.)
tests/                      # Test suites (mirrors src/ structure)
  cli/                      # CLI command tests
  core/                     # Core logic and security rule tests
  fix-tests/                # Fix command tests
  utils/                    # Shared test utilities
scripts/                    # Build scripts (CLI compilation)
docs/                       # Documentation (user guide)
.claude/                    # Claude Code configuration and skills
```

Each CLI command follows a Command-Coordinator pattern: `command.ts` handles presentation (prompts, formatting, console output) while `coordinator.ts` handles business logic and returns structured results. See [.claude/CLAUDE.md](.claude/CLAUDE.md) for the full pattern, dependency rules, and conventions.

## Testing

The project uses [Vitest](https://vitest.dev/) as its test framework.

```bash
npm test                # Run all tests
npm run test:watch      # Watch mode
npm run test:coverage   # Coverage report
```

Test organization:
- `tests/cli/` — CLI command registration and binary utilities
- `tests/core/scanners/srt/rules/{service}/` — security rule tests with compliant/non-compliant CloudFormation scenarios
- `tests/fix-tests/` — fix command logic
- `tests/utils/` — shared test utilities

## Building CLI Binaries

Bun compiles the TypeScript source into standalone executables for each platform.

```bash
npm run build:cli:all            # All platforms
npm run build:cli:linux-x64      # Linux x64
npm run build:cli:linux-arm64    # Linux ARM64
npm run build:cli:osx-x64        # macOS Intel
npm run build:cli:osx-arm64      # macOS ARM
npm run build:cli:win-x64        # Windows
```

Output is written to `build/<platform>/srt` (or `srt.exe` on Windows). Use the `:prod` script variants (e.g., `npm run build:cli:all:prod`) for production builds with minification and sourcemaps.

## Adding Security Rules

SRT includes a Claude Code skill for generating security matrix rules. This skill automates the creation of new security checks that scan CloudFormation templates for AWS security best practices violations.

**Prerequisites:**
- [Claude Code](https://claude.com/claude-code) CLI installed
- Project opened in Claude Code

**To generate a new security rule:**

```bash
# In Claude Code, invoke the skill
/security-rule-generator
```

Claude Code will guide you through:
1. **Rule ID**: Format `SERVICE-###` (e.g., S3-010, KMS-003)
2. **Resource types**: AWS CloudFormation resource types to check
3. **Security requirement**: What security property to validate
4. **Priority**: HIGH, MEDIUM, or LOW

The skill automatically:
- Fetches relevant AWS documentation
- Reviews existing rule patterns in the codebase
- Generates the rule implementation following project conventions
- Creates unit tests with compliant/non-compliant scenarios
- Registers the rule in the appropriate service index

**Example:**
```
User: /security-rule-generator
Claude: What security rule would you like to create?
User: S3 buckets should have intelligent tiering enabled
Claude: [Gathers requirements, generates S3-011 rule and tests]
```

Rules are created at `src/assess/scanning/security-matrix/rules/{service}/` with corresponding tests at `tests/core/scanners/srt/rules/{service}/`.

## CI/CD

The project uses GitHub Actions. Workflow files are in `.github/workflows/`.

| Workflow | Trigger | Description |
|---|---|---|
| **pr.yml** | PRs to `main` (non-release) | Build, test, coverage report comment |
| **release.yml** | Release PR merged | Build, test, build binaries, create GitHub Release, delete branch |

## Branching Strategy & Releases

### Branches

- **main** — production branch (protected, requires PRs)
- **feature branches** — short-lived branches for features and fixes, merged directly into `main`
- **release/v*** — short-lived release branches, created and deleted automatically by the release workflow

### Creating a Release

> **Before running the script, merge your changes into `main`.** The release script operates entirely off `origin/main` — it checks out and pulls `main`, then cuts the `release/v*` branch from there. Any commits that live only on a feature branch will **not** be included in the release. Ensure your feature PRs are merged (and `main` is green) before invoking it.

Run the release script from the repository root:

```bash
./scripts/release.sh patch   # or minor, major, or explicit version (e.g., 1.2.3)
```

The script automates the full release pipeline:

1. Checks out the latest `origin/main` and cuts a new `release/v*` branch from it, then bumps the version in `package.json`
2. Pushes the branch and opens a PR with auto-merge enabled
3. Once the PR merges, the **release** workflow builds binaries for all platforms, creates a GitHub Release with the archives, and deletes the release branch
