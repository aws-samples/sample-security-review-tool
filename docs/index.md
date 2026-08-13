# Security Review Tool

A CLI tool for performing security reviews on AWS CDK and CloudFormation projects. It scans CloudFormation templates and CDK constructs for security issues, generates data flow diagrams and threat models, and produces detailed assessment reports. Built with TypeScript, Commander.js, and Amazon Bedrock.

For end-user documentation (installation, CLI usage, CI/CD integration), see [docs/USER-GUIDE.md](docs/USER-GUIDE.md). For architecture patterns and code conventions, see [.claude/CLAUDE.md](.claude/CLAUDE.md).

## Prerequisites

- [Node.js](https://nodejs.org/) 22+
- [Git](https://git-scm.com/downloads)
- [Bun](https://bun.sh/) (required for CLI binary compilation and for the rule builder)
- AWS credentials with `bedrock:InvokeModel` permission (env vars, SSO, named profiles, or federated roles)
- [Terraform](https://developer.hashicorp.com/terraform/install) on your `PATH` (required by the rule builder to validate Terraform fixtures and fixes)
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
rule-builder/               # Separate CLI that builds, converts, and exercises security rules
fixtures/                   # Generated per-rule fixture projects (cdk, cfn, terraform)
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

Security rules are built by the **rule builder**, a separate CLI in `rule-builder/`. It drives Bedrock through a five-phase pipeline and writes the rule, its tests, and its fixtures for you. Run every command from the `rule-builder` folder.

### Build a new rule

```bash
cd rule-builder
bun src/index.ts --rule S3-011 --service s3 --description "S3 buckets must have intelligent tiering enabled"
```

`--rule`, `--service`, and `--description` are all required to build. Add `--regenerate` to clear the existing tests, control, and adapter files first (cached requirements are kept).

### Convert an existing rule

```bash
bun src/index.ts --convert LAMBDA-013
```

The rule ID, service, and description are read from the legacy rule's own source, so `--rule`, `--service`, and `--description` must not be passed alongside `--convert`. The description is restated as a requirement ("X-Ray tracing not enabled" becomes "Lambda functions must have X-Ray tracing enabled"), and the service prefix loses its hyphens (`API-GW-002` becomes `APIGW-002`).

The legacy files are left in place. The run ends by listing them — the old rule sources, the service `index.ts`, and the old tests — so you can compare the new findings against the old ones before deleting anything.

### Exercise an existing rule

```bash
bun src/index.ts --rule S3-011
```

Runs the rule's unit tests and remediation against its existing fixtures. Nothing is regenerated; the service and description are recovered from the rule's `requirements.json`.

### The five phases

| Phase | What it does |
|---|---|
| 1. Requirements | Turns the description into a list of testable requirements, cached as `{rule-id}.requirements.json` |
| 2. Scaffolding | Writes the control file and the CFN and Terraform adapters |
| 3. Implementation | Fills in the control logic and unit tests, then verifies the tests pass |
| 4. Fixtures | Generates compliant and non-compliant CDK, CloudFormation, and Terraform projects |
| 5. Remediation | Runs `assess` and `fix` against the fixtures, then re-verifies the unit tests |

A failing unit test after phase 3 or phase 5 stops the run.

### Where the output lands

| Path | Contents |
|---|---|
| `src/assess/scanning/security-matrix/rules/{service}/{rule-id}/` | `.control.ts`, `.adapter.ts`, `.adapter.cfn.ts`, `.adapter.tf.ts`, `.requirements.json` |
| `tests/core/scanners/srt/rules/{service}/{rule-id}/` | Unit tests |
| `fixtures/{rule-id}/{cdk,cfn,terraform}/` | Fixture projects used by phases 4 and 5 |

Logs are written to `~/.srt/logs`. Bedrock is called with the `default` AWS profile in `us-east-1`.

### Legacy rules

Not every rule has been converted yet. The unconverted ones still use the older flat layout, a single `{service}/###-name.cf.ts` file paired with a `.tf.ts` file. Convert them with `--convert` rather than editing them in place.

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
