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

### Environment Configuration

API endpoints are injected at build time via Bun's `--define` flags. Copy `.env.example` to `.env` and fill in real values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `COGNITO_APP_CLIENT_ID` | Cognito user pool app client ID for authentication |
| `COGNITO_DOMAIN` | Cognito hosted UI domain URL |

The `.env` file is gitignored. These values are baked into the CLI binary at build time — they are not read at runtime.

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

Bun compiles the TypeScript source into standalone executables for each platform. The `.env` values are injected at compile time via `--define` flags.

```bash
npm run build:cli:all          # All platforms
npm run build:cli:linux-x64    # Linux x64
npm run build:cli:osx-x64      # macOS Intel
npm run build:cli:osx-arm64    # macOS ARM
npm run build:cli:win-x64      # Windows
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

## GitLab MCP Server

The project includes a `.mcp.json.example` template for configuring the GitLab MCP server, which enables Claude Code to interact with the GitLab project directly — creating issues, merge requests, and more.

### Setup

1. **Copy the example configuration:**

   ```bash
   cp .mcp.json.example .mcp.json
   ```

2. **Edit `.mcp.json`** and fill in your GitLab instance URL and project ID:

   | Field | Description |
   |---|---|
   | `GITLAB_API_URL` | Your GitLab instance API URL (e.g., `https://gitlab.example.com/api/v4`) |
   | `GITLAB_PROJECT_ID` | Numeric project ID (found on the project's main page in GitLab) |

3. **Generate a GitLab personal access token** from your GitLab instance under **User Settings > Access Tokens** with `api` scope.

4. **Export the token** as an environment variable before launching Claude Code:

   ```bash
   export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxxx
   ```

   The `.mcp.json` references `${GITLAB_TOKEN}`, which Claude Code resolves from your environment at startup.

5. **Launch Claude Code** from the project root. The MCP server starts automatically — no additional install is needed.

### Creating Issues

Ask Claude Code to create an issue in natural language:

```
Create an issue titled "Add S3 lifecycle policy rule" with description
"Implement a new security rule that checks S3 buckets have lifecycle
policies configured."
```

Claude Code uses the GitLab MCP server to call `create_issue` with the title, description, and any labels you specify.

### Adding Issues to the Backlog Board Column

GitLab issue boards organize issues into columns based on labels. To place a new issue in the **Backlog** column, include the `Backlog` label when creating it:

```
Create an issue titled "Add RDS encryption rule" with label "Backlog"
```

You can also add the label to an existing issue:

```
Add the "Backlog" label to issue #42
```

To move an issue out of Backlog into another column, ask Claude Code to swap the label:

```
Remove the "Backlog" label from issue #42 and add "In Progress"
```

### Other Common Operations

| Task | Example prompt |
|---|---|
| List open issues | `List open issues in the project` |
| View an issue | `Show me issue #15` |
| Add a comment | `Add a comment to issue #15: "Fixed in MR !23"` |
| Create a merge request | `Create an MR from branch feature/s3-lifecycle targeting develop` |
| List labels | `List all labels in the project` |

## CI/CD

The project uses GitLab CI with five stages. See `.gitlab-ci.yml` for full configuration.

| Stage | Trigger | Description |
|---|---|---|
| **test** | All branches | TypeScript build + Vitest coverage |
| **version** | `main` branch | Version validation and release prep |
| **release** | `main` branch | Builds all platform binaries and creates a GitLab release |
