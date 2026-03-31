---
name: security-rule-debugger
description: Debugs security matrix rules that trigger false positives. Use when investigating why a rule flagged a compliant resource, understanding rule logic, or fixing rule bugs.
---

# Security Rule Debugger

Analyzes security matrix rules against CloudFormation resources to diagnose false positives and suggest fixes.

## When to Use

- User reports a false positive from a security rule
- User wants to understand why a specific rule triggered
- User pastes CLI output showing a security finding
- User asks to trace or debug rule evaluation logic

## Process

### 1. Gather Information

Ask the user for:

**Option A - CLI Output (preferred):**
```
Issue: ECS task may not be using secure parameter storage...
Resource Type: AWS::ECS::TaskDefinition
Resource Name: coretaskdefinition9BB3B725
File: C:\git\project\infrastructure\core.ts
Fix: Store sensitive parameters in AWS Secrets Manager...
```

**Option B - Manual input:**
- Rule ID: Format `SERVICE-###` (e.g., ECS-002)
- Template path or resource snippet
- Resource logical ID

**Required for both:**
- Project path (to locate `.srt/issues.json`)

### 2. Resolve Rule from CLI Output

If CLI output provided, extract the rule ID from `.srt/issues.json`:

```typescript
// 1. Parse CLI output to extract:
const resourceName = "coretaskdefinition9BB3B725";  // from "Resource Name:" line
const issueText = "ECS task may not be using...";   // from "Issue:" line

// 2. Read the issues file
Read: {project-path}/.srt/issues.json

// 3. Find matching issue
const match = issues.find(i =>
  i.source === "security-matrix" &&
  i.resourceName === resourceName &&
  i.issue.includes(issueText.substring(0, 50))  // partial match
);

// 4. Extract rule info
const ruleId = match.check_id;        // e.g., "ECS-002"
const templatePath = match.path;       // e.g., "cdk.out/stack.template.json"
const resourceType = match.resourceType;
```

**issues.json entry structure:**
```json
{
  "source": "security-matrix",
  "path": "cdk.out\\changelogs-md-core.template.json",
  "resourceType": "AWS::ECS::TaskDefinition",
  "resourceName": "coretaskdefinition9BB3B725",
  "issue": "ECS task may not be using secure parameter storage...",
  "fix": "Store sensitive parameters in AWS Secrets Manager...",
  "priority": "HIGH",
  "check_id": "ECS-002",
  "status": "Open",
  "cdkPath": "changelogs-md-core/core-task-definition/Resource"
}
```

### 3. Load Rule Source

Read the rule implementation. The rule ID format is `SERVICE-###` (e.g., ECS-002).

Map the service prefix to folder:
- `ECS` -> `ecs/`
- `S3` -> `s3/`
- `KMS` -> `kms/`
- etc.

```
src/assess/scanning/security-matrix/rules/{service}/{###}-{rule-name}.ts
```

To find the exact file, use Glob:
```
Glob: src/assess/scanning/security-matrix/rules/{service}/*.ts
```

Extract and document:
- Rule ID, priority, description
- Applicable resource types (`applicableResourceTypes`)
- Evaluation method used (`evaluateResource` or `evaluate`)
- Helper methods and their logic
- Pattern arrays (regex/string checks)

### 4. Parse the Resource

Read the CloudFormation template using the `path` from issues.json:
```typescript
// Template path from issues.json (relative to project root)
Read: {project-path}/{templatePath}
// e.g., C:\git\project\cdk.out\stack.template.json
```

Extract the specific resource by logical ID (`resourceName` from issues.json).

Document:
- Resource Type
- Resource Logical ID
- Relevant properties that the rule examines

### 5. Trace Evaluation Logic

Walk through the rule's code path step-by-step with actual values:

**5.1 Type Check**
```
rule.appliesTo(resource.Type) -> {true|false}
```

**5.2 Property Extraction**
Document what properties the rule reads:
```
resource.Properties.{PropertyName} -> {actual value}
```

**5.3 Conditional Branches**
Trace each `if` statement the rule executes:
```
Line X: if (condition) -> {true|false}
  Input: {actual value}
  Expected: {what the rule checks for}
```

**5.4 Pattern Matching**
For each pattern check, document:
```
Pattern: /secretsmanager/i
Input: {"Fn::ImportValue": "stack:ExportName"}
Stringified: '{"Fn::ImportValue":"stack:ExportName"}'
Match: false
```

**5.5 Intrinsic Function Handling**
Check how the rule handles CloudFormation intrinsics:
- `hasIntrinsicFunction()` result
- `containsPattern()` results
- `extractResourceIdsFromReference()` results

### 6. Diagnose the Issue

Classify the finding:

| Classification | Description |
|----------------|-------------|
| **True Positive** | Rule correctly identified a security issue |
| **False Positive - Rule Bug** | Rule logic doesn't handle a valid pattern |
| **False Positive - Edge Case** | Valid but unusual pattern not anticipated |
| **Indeterminate** | Cannot determine without runtime context |

### 7. Generate Fix (if False Positive)

If a rule bug is identified:

**7.1 Explain the Gap**
Describe specifically why the rule's logic fails for this case.

**7.2 Provide Code Fix**
```typescript
// In {file-path}, modify {method-name}:

// Before:
{old code}

// After:
{new code with fix}
```

**7.3 Add Test Case**
```typescript
// In tests/core/scanners/srt/rules/{service}/{###}-rule-name.test.ts

it('should handle {specific scenario}', () => {
  const template: Template = {
    Resources: {
      TestResource: {
        Type: 'AWS::Service::Resource',
        Properties: {
          // Properties that trigger the false positive
        }
      }
    }
  };

  const result = rule.evaluateResource(stackName, template, template.Resources!['TestResource'] as Resource);
  expect(result).toBeNull(); // Should not flag valid resource
});
```

## Output Format

```markdown
## Rule Analysis: {RULE-ID}

### Rule Details
| Property | Value |
|----------|-------|
| ID | {id} |
| Priority | {priority} |
| Description | {description} |
| Applies To | {resource types} |
| Method | evaluateResource / evaluate |

### Resource Under Analysis
**Logical ID**: {resourceId}
**Type**: {resourceType}

**Relevant Properties**:
```json
{extracted properties}
```

### Evaluation Trace

| Step | Location | Input | Result | Notes |
|------|----------|-------|--------|-------|
| 1 | appliesTo() | AWS::ECS::TaskDefinition | true | Type matches |
| 2 | line 28 | ContainerDefinitions | [{...}] | Array with 1 container |
| ... | ... | ... | ... | ... |

### Pattern Matching Results

| Pattern | Checked Against | Match? |
|---------|-----------------|--------|
| /secretsmanager/i | {"Fn::ImportValue":"..."} | No |
| /ssm/i | {"Fn::ImportValue":"..."} | No |
| ... | ... | ... |

### Diagnosis

**Result**: {True Positive | False Positive | Edge Case}

**Explanation**:
{Detailed explanation of why the rule triggered or failed to handle the case}

### Recommended Fix

**Problem**: {specific gap in rule logic}

**Solution**:
```typescript
// File: {path}
// Method: {method name}

// Add this check:
{code}
```

**Test Case**:
```typescript
{test code}
```
```

## Key Files Reference

When debugging, read these files for context:

| File | Purpose |
|------|---------|
| `src/assess/scanning/security-matrix/security-rule-base.ts` | Base class with `appliesTo`, `createResult` |
| `src/assess/scanning/utils/cloudformation-intrinsic-utils.ts` | `hasIntrinsicFunction`, `containsPattern`, `extractResourceIdsFromReference` |
| `src/assess/scanning/security-matrix/resolver.ts` | `CloudFormationResolver` for resolving intrinsics |
| `src/assess/scanning/security-matrix/cfn-utils.ts` | Template parsing utilities |
| `src/assess/scanning/security-matrix/matrix-scanner-engine.ts` | How rules are executed |

## Common Patterns Reference

See [DEBUGGING-GUIDE.md](DEBUGGING-GUIDE.md) for:
- Common false positive causes
- Intrinsic function handling gaps
- CDK-specific patterns
- Cross-stack reference issues
