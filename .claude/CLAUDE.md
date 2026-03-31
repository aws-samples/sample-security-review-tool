# SRT Architecture

Follow Robert C. Martin's Clean Code principles (small functions, intention-revealing names, SRP, no side effects, DRY). This document covers project-specific patterns.

## Structure

```
src/
  index.ts              # CLI entry point
  assess/               # Assess command
  config/               # Config command
  fix/                  # Fix command
  status/               # Status command
  update/               # Update command
  shared/               # Cross-cutting utilities
    ai/                 # Bedrock client
    app-config/         # Application configuration
    cdk/                # CDK utilities
    command-execution/  # Process/command runner
    error-handling/     # Error handling
    file-system/        # File utilities
    logging/            # MCP logger
    persistence/        # Settings manager
    project-analysis/   # Project/CFN helpers
    utils/              # Misc utilities
```

## Core Patterns

### Feature Organization
Each CLI command = one feature folder containing all related logic. Minimize cross-feature dependencies.

```
feature/
  command.ts          # CLI presentation only
  coordinator.ts      # Orchestrates business workflow
  types.ts            # Local type definitions
  subfolder/          # Group related components (when >4-5 files)
```

### Command (command.ts)
- Presentation layer only: inquirer prompts, chalk formatting, console.log
- Instantiates coordinator, calls methods, displays results
- NO business logic

### Coordinator (coordinator.ts)
- Orchestrates business workflow
- Emits progress via callback: `onProgress({ phase, details })`
- Returns structured results with errors
- NO console output

### Dependencies
Coordinators instantiate their own dependencies directly:
```typescript
// ✅ Coordinator owns dependencies
export class AwsSetup {
  private credentialsReader = new AwsCredentialsReader();
  private bedrockValidator = new BedrockValidator();
}

// ❌ Don't inject unless needed for testing expensive operations
constructor(repo: IAwsProfileRepository, validator: IBedrockValidator) {}
```

### Error Handling
Return errors as data; let command display them:
```typescript
// Coordinator
async validateAndSave(profile: string): Promise<ValidationResult> {
  try {
    return await this.validator.validate(profile);
  } catch (error) {
    return { isValid: false, errors: [error.message] };
  }
}

// Command
const result = await setup.validateAndSave(profile);
if (!result.isValid) {
  result.errors.forEach(e => console.log(chalk.red(e)));
}
```

### Subfolder Organization
Group related components when complexity grows:
```
// ✅ Group related components
config/
  aws/
    aws-setup.ts
    bedrock-validator.ts
  path/
    path-setup.ts
    shell-config-updater.ts

// ❌ Flat structure becomes unwieldy
config/
  aws-setup.ts
  path-setup.ts
  bedrock-validator.ts
  shell-config-updater.ts
```

## Dependency Rules

- Features import from `shared/`, never the reverse
- Shared code must never import from feature folders
- Features should not import from other features

## Anti-Patterns

### ❌ Business Logic in Command
```typescript
export class ConfigCommand {
  private static async execute(): Promise<void> {
    const profiles = await readAwsProfiles();
    const defaultProfile = profiles.find(p => p.isDefault) || profiles[0]; // BAD
  }
}
```

### ✅ Business Logic in Coordinator
```typescript
export class AwsSetup {
  public determineDefaultProfile(profiles: AwsProfile[]): AwsProfile | undefined {
    return profiles.find(p => p.isDefault) || profiles[0];
  }
}
```

### ❌ Console Output in Coordinator
```typescript
export class StatusCoordinator {
  public async getStatus(path: string): Promise<void> {
    console.log('Getting status...'); // BAD - side effect
  }
}
```

### ✅ Return Data, Command Displays
```typescript
export class StatusCoordinator {
  public async getStatus(path: string): Promise<StatusResult> {
    return { openIssues, resolvedIssues };
  }
}
// Command handles display
const status = await coordinator.getStatus(path);
console.log(`Open: ${status.openIssues}`);
```

## Formatting

- Method signatures on single line unless >120 characters
- Avoid excessive bullet points and headers in documentation
- Keep files under 200-500 lines