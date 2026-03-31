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
| **ci.yml** | Reusable | TypeScript build + Vitest test suite |
| **main-ci.yml** | Push to `main` | Runs CI on main branch |
| **pr-checks.yml** | PRs to `main` | Runs CI and posts a coverage report comment |
| **auto-tag.yml** | Release PR merged | Creates a version tag from `package.json` |
| **release.yml** | Version tag (`v*`) | Builds all platform binaries and creates a GitHub Release |

## Branching Strategy & Releases

### Branches

- **main** — production branch (protected, requires PRs)
- **develop** — integration branch for feature work
- **feature/** — feature branches, typically targeting `develop` or `main`
- **release/v*** — short-lived release branches, created by the release script

### Creating a Release

Run the release script from the repository root:

```bash
./scripts/release.sh patch   # or minor, major
```

The script automates the full release pipeline:

1. Bumps the version in `package.json` on a new `release/v*` branch
2. Pushes the branch and opens a PR with auto-merge enabled
3. CI runs; once it passes, the PR is squash-merged into `main`
4. The **auto-tag** workflow detects the merged release PR and creates a `v*` tag
5. The **release** workflow triggers on the tag, builds binaries for all five platforms, and publishes a GitHub Release with the archives
