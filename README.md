---
title: User Guide
---

# Security Review Tool User Guide

A guide for using the SRT CLI tool to perform security reviews on AWS CDK and CloudFormation projects.

## Prerequisites

- Git ([Download](https://git-scm.com/downloads))
- AWS credentials with `bedrock:InvokeModel` permission. Supported credential sources:
  - Environment variables (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`)
  - SSO sessions (`aws sso login`)
  - Named or default AWS profiles (`~/.aws/credentials`)
  - Federated roles (e.g., IAM Identity Center)
- AWS CDK (only required when using this tool for CDK projects)

## Installation

Download the latest release of the SRT CLI Tool for your platform from the [releases page](https://github.com/aws/security-review-tool/releases).

After downloading, extract the package to a local folder.

> **Mac users:** If you see a "file damaged and can't be opened" warning on first launch, run this command in Terminal: `xattr -d com.apple.quarantine ./srt`

## SRT Configuration

Before performing an analysis, you must configure the SRT CLI tool by running:

```bash
srt config
```

During the configuration process, you will be prompted to:

1. **Select your AWS profile**: Provide the AWS profile to use to connect to Amazon Bedrock. This profile requires the `bedrock:InvokeModel` permission. When using the `default` profile, the tool will also check environment variables and federated credentials automatically
2. **Add SRT CLI to system PATH** (recommended): Choose whether to automatically add the SRT CLI to your system PATH so it can be run from anywhere

This configuration is required before you can use the tool for security assessments.

## Project License Configuration

The first time you perform an SRT assessment on a project you will be prompted to select a license for that project. This license determines the license header that will be added to all code files in your project during the SRT process.

Available licenses:

- **AWS** (default): Uses the AWS Content license under the AWS Enterprise Agreement or AWS Customer Agreement.
- **MIT**: Uses the MIT License, a permissive license with minimal restrictions.
- **Apache**: Uses the Apache License 2.0, which provides an express grant of patent rights.

If you are unsure which license to use, select 'AWS' as the default option.

### Handling Existing License Headers

When running the SRT assessment on a project that already contains files with license headers, the tool will detect these existing headers during the Assess command. If the existing license headers don't match the supported licenses, you will be presented with the following options:

1. **Keep existing license headers**: Choose this option if you want to preserve the existing license headers in your code files. No changes will be made to any code files and you will be responsible for manually prepending license headers to all code files in your project.

2. **Replace existing license headers**: Choose this option if you want to replace all existing license headers with the license you configured for your project. This ensures consistency across all files in your project.

3. **Exit without making changes**: Choose this option to cancel the SRT process without modifying any license headers. This allows you to review your project's license headers manually before proceeding.

This prompt only appears when the tool detects license headers that don't match any of the supported licenses. If all existing license headers already match a supported license, or if there are no existing license headers, the tool will proceed with the assessment without prompting.

## Usage

### Basic Usage

```bash
# Basic usage - run SRT assessment on current directory
srt [assess]

# Configure region, profile, Model ID, and License Type
srt config

# Iterate through findings
srt fix

# Update to the latest version of SRT
srt update

# Show help information
srt --help

# Show version information
srt --version
```

### Assess Command

The `assess` command is the primary function of SRT and is the default command when running `srt` without any subcommand. It performs a comprehensive security assessment of your AWS infrastructure code.

#### Command Options

```bash
srt [assess] [options]
```

**Available Options:**

- `-p, --path <project-path>`: Specify the project root folder path to assess (defaults to current directory)
- `-l, --license <license-type>`: Set the software license type for code files (choices: `aws`, `mit`, `apache`)
- `--no-license-update`: Skip license header updates
- `--no-diagrams`: Skip diagram generation to speed up the assessment process
- `--no-threat-models`: Skip threat model generation to speed up the assessment process
- `--cdk-out <path>`: Path to a pre-existing CDK output directory containing synthesized CloudFormation templates (skips CDK synthesis). Can be specified multiple times for multiple CDK output directories
- `-y, --yes`: Use default values for all prompts (non-interactive mode)
- `--help`: Display help information
- `--version`: Display version information

#### Usage Examples

```bash
# Basic assessment of current directory (interactive mode)
srt
# or explicitly:
srt assess

# Assess a specific project directory
srt assess -p /path/to/my-project

# Set license type during assessment
srt assess -l mit

# Skip license header updates during assessment
srt assess --no-license-update

# Skip diagram and threat model generation for faster assessment
srt assess --no-diagrams --no-threat-models

# Non-interactive mode with defaults
srt assess -y

# Combined options: assess specific path with Apache license, skip diagrams, non-interactive
srt assess -p ./my-aws-project -l apache --no-diagrams -y

# Assess with custom path and skip threat models only
srt assess -p /home/user/projects/infrastructure --no-threat-models

# Use a pre-existing CDK output directory (skips CDK synthesis)
srt assess --cdk-out ./cdk.out

# Use multiple CDK output directories
srt assess --cdk-out ./project-a/cdk.out --cdk-out ./project-b/cdk.out
```

#### Interactive vs Non-Interactive Mode

**Interactive Mode (default):**
- Prompts for project root folder path (if not specified with `-p`)
- Prompts for license selection (if not specified with `-l` and no existing project license)
- Prompts for handling existing license headers (if non-conforming headers are found)

**Non-Interactive Mode (`-y` flag):**
- Uses current directory as project path (unless `-p` is specified)
- Uses AWS license as default (unless `-l` is specified or project already has a configured license)
- Automatically updates non-conforming license headers without prompting

#### Assessment Components

The assess command performs the following analysis steps:

1. **Project Discovery**: Identifies CloudFormation templates and CDK constructs
2. **License Management**: Ensures all code files have appropriate license headers
3. **Data Flow Analysis**: Generates visual diagrams showing data flow between resources (unless `--no-diagrams` is used)
4. **Security Matrix Review**: Performs comprehensive security analysis using multiple scanning engines
5. **Code Analysis**: Scans for security vulnerabilities in infrastructure code
6. **Threat Modeling**: Generates detailed threat models for identified resources (unless `--no-threat-models` is used)

The assessment results are saved in a `.srt` folder within your project directory and include detailed reports, findings, and any generated diagrams or threat models.

### Fix Command

SRT can help you fix security issues identified during an assessment:

```bash
# Fix high-priority security issues
srt fix
```

When you run the `srt fix` command, the tool will:

1. Check for open high-priority security issues
2. Present each issue with details including:
   - File path
   - Resource type and name
   - Issue description
   - Recommended fix

For each issue, you'll be presented with the following options:

- **Suppress this finding**: Mark the issue as suppressed (see [Issue Suppression](#issue-suppression) below)
- **Skip for now**: Keep the issue open to address later
- **Exit**: Exit the fix process

The `srt fix` command helps you systematically address security issues in your project, focusing on high-priority items first.

### Issue Suppression

When a security finding is not applicable to your project, you can suppress it to exclude it from future open issue lists. This is useful for false positives or findings that are intentionally accepted.

#### Suppression Workflow

When you choose **Suppress this finding** in the `srt fix` command, you will be prompted to select a reason:

- **This is a false-positive**: The finding does not represent an actual security issue in your context
- **This is not required/permitted by the customer**: The security control is not applicable due to customer requirements
- **Other**: Enter a custom reason describing why the finding is being suppressed
- **Go back**: Return to the previous action menu without suppressing

#### How Suppressed Issues Are Stored

Suppressed issues are saved in `.srt/issues.json` with a `suppressed` status and the reason you provided. The suppression reason is displayed in the SRT dashboard report alongside the issue details.

#### Behavior Across Assessments

Suppressed issues remain suppressed in subsequent assessment runs. They will not reappear in the open issues list when you run `srt fix`, even if the underlying code has not changed. This allows you to run repeated assessments without being prompted about previously reviewed findings.

## CI/CD Pipeline Integration

SRT can be integrated into your CI/CD pipeline to perform automated security assessments on your infrastructure code. This enables continuous security validation as part of your development workflow.

### Prerequisites for CI/CD

- **SRT Executable**: The SRT CLI binary must be included in your source code repository

### Including SRT in Your Repository

1. **Download the SRT Binary**: Download the appropriate SRT CLI binary for your CI/CD environment from the [releases page](https://github.com/aws/security-review-tool/releases)

2. **Choose the Right Platform**: Most CI/CD environments run on Linux, so download the Linux x64 binary (`srt-cli-vX.X.X-linux-x64.tar.gz`)

3. **Add to Repository**: Extract and include the SRT executable in your repository:
   ```bash
   # Create a tools directory (recommended)
   mkdir -p tools/srt

   # Extract the SRT binary to the tools directory
   tar -xzf srt-cli-vX.X.X-linux-x64.tar.gz -C tools/srt/

   # Make executable (if needed)
   chmod +x tools/srt/srt

   # Commit to repository
   git add tools/srt/srt
   git commit -m "Add SRT binary for CI/CD integration"
   ```

4. **Update .gitignore**: Ensure the SRT binary is **not** ignored in your `.gitignore` file. The executable must be checked into version control.

### Pipeline Configuration

#### Basic Command Structure

For CI/CD integration, use SRT with these required flags for non-interactive, faster execution:

```bash
./tools/srt/srt assess --path <project-root> --no-diagrams --no-threat-models --yes [--license <type>] [--cdk-out <path>]
```

**Required Flags:**
- `--path <project-root>`: Specify the absolute or relative path to your project root folder (the folder containing the `.git` directory)
- `--no-diagrams`: Skip diagram generation (reduces execution time and eliminates graphical dependencies)
- `--no-threat-models`: Skip threat model generation (reduces execution time and AI model usage)
- `--yes`: Use default values for all prompts (enables non-interactive mode)

**Optional Flags:**
- `--license <type>`: Specify license type (`aws`, `mit`, or `apache`). If omitted, defaults to AWS license
- `--cdk-out <path>`: Path to a pre-existing CDK output directory. Useful when your pipeline already runs `cdk synth` as a separate build step. Can be specified multiple times for multiple CDK output directories
