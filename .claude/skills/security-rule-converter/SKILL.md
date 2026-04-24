---
name: security-rule-converter
description: Converts old-style security matrix rules (using evaluate/createScanResult) to the new evaluateResource/createResult pattern. Use when migrating existing rules to the new implementation style. Specify a rule ID like LAMBDA-004 or S3-002.
---

# Security Rule Converter

Converts legacy security matrix rules from the old `evaluate`/`createScanResult` pattern to the new `evaluateResource`/`createResult` pattern.

## When to Use

- User asks to convert/migrate/update a security rule to the new pattern
- User provides a rule ID (e.g., LAMBDA-004, EKS-001) to convert
- User wants to modernize a rule implementation

## Process

### 1. Locate the Rule

Parse the rule ID provided by the user. The format is `SERVICE-###` (e.g., LAMBDA-004, S3-002).

Map the service prefix to the folder name (lowercase, with hyphens where needed):

```
LAMBDA -> lambda/
S3 -> s3/
EC2 -> ec2/
EKS -> eks/
ECS -> ecs/
IAM -> iam/
KMS -> kms/
RDS -> rds/
API-GW -> api-gateway/
```

Find the rule file:
```
Glob: src/assess/scanning/security-matrix/rules/{service}/*{number}*.ts
```

Read the rule file and its test file:
```
src/assess/scanning/security-matrix/rules/{service}/{###}-{name}.ts
tests/core/scanners/srt/rules/{service}/{###}-{name}.test.ts
```

### 2. Analyze the Existing Rule

Determine the rule's complexity category:

**Simple (single-resource check):** The rule only inspects `resource.Properties` on the current resource. No use of `allResources`. Convert directly to `evaluateResource`.

**Cross-resource:** The rule uses `allResources` to find related resources (e.g., checking if a CloudWatch alarm exists for a Lambda function). Convert to `evaluateResource` using `template.Resources` instead.

**CloudFormationResolver-dependent:** The rule imports and uses `CloudFormationResolver` to resolve intrinsic functions across `allResources`. These rules require careful conversion — the resolver may still be needed but should operate on template data.

### 3. Convert the Rule

Apply these transformations:

#### 3.1 Imports

Ensure the import line includes `Resource`:
```typescript
// Before
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

// After
import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';
```

#### 3.2 Primary Evaluation Method

Move logic from `evaluate` into `evaluateResource`:

```typescript
// Before
public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
  if (resource.Type === 'AWS::Lambda::Function') {
    const prop = resource.Properties?.SomeProp;
    if (!prop) {
      return this.createScanResult(resource, stackName, this.description, 'Fix message');
    }
  }
  return null;
}

// After
public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
  if (resource.Type !== 'AWS::Lambda::Function') return null;

  const prop = resource.Properties?.SomeProp;
  if (!prop) {
    return this.createResult(stackName, template, resource, this.description, 'Fix message');
  }

  return null;
}

public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
  return null;
}
```

#### 3.3 Result Creation

Replace `createScanResult` with `createResult`. Note the parameter order change:

```typescript
// Before (old)
this.createScanResult(resource, stackName, issue, fix)

// After (new)
this.createResult(stackName, template, resource, issue, fix)
```

Key differences:
- `createScanResult(resource, stackName, issue, fix?)` — fix is optional
- `createResult(stackName, template, resource, issue, fix)` — fix is required, template is added

#### 3.4 Cross-Resource References

Replace `allResources` array lookups with `template.Resources`:

```typescript
// Before
const related = allResources?.find(r => r.Type === 'AWS::CloudWatch::Alarm' && r.Properties?.Namespace === 'AWS/Lambda');

// After
const related = Object.entries(template.Resources || {}).find(([id, r]) =>
  r.Type === 'AWS::CloudWatch::Alarm' && r.Properties?.Namespace === 'AWS/Lambda'
);
```

#### 3.5 Logical ID Access

In old-style rules, `resource.LogicalId` is directly available. In new-style rules, look it up from the template when needed (or use helper methods):

```typescript
// Finding the current resource's logical ID from the template
const logicalId = Object.keys(template.Resources || {}).find(
  key => template.Resources![key] === resource
);
```

#### 3.6 Type Guard Pattern

Prefer early-return guard over wrapping in `if`:

```typescript
// Before (old pattern - wraps in if)
if (resource.Type === 'AWS::Lambda::Function') {
  // ... all logic indented
}
return null;

// After (new pattern - early return guard)
if (resource.Type !== 'AWS::Lambda::Function') return null;
// ... logic at top level
return null;
```

Alternatively, use `appliesTo` for the guard:
```typescript
if (!this.appliesTo(resource.Type)) return null;
```

#### 3.7 JSDoc Update

Update the JSDoc to reflect the new entry point:

```typescript
// Before
/**
 * LAMBDA-004: Lambda functions must have AWS X-Ray active tracing enabled.
 *
 * Uses the single-resource evaluate entry point to inspect each
 * AWS::Lambda::Function resource individually.
 */

// After
/**
 * LAMBDA-004: Lambda functions must have AWS X-Ray active tracing enabled.
 *
 * Uses the template-aware evaluateResource entry point to inspect each
 * AWS::Lambda::Function resource individually.
 */
```

#### 3.8 Stub the Legacy Method

The old `evaluate` method becomes a stub returning `null`:

```typescript
public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
  return null;
}
```

### 4. Convert the Tests

Transform test file from old pattern to new pattern:

#### 4.1 Test Imports

```typescript
// Before
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

// After
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';
```

#### 4.2 Test Data Structure

Replace `CloudFormationResource` objects with `Template` objects:

```typescript
// Before
function createResource(props: Record<string, any> = {}): CloudFormationResource {
  return {
    Type: 'AWS::Lambda::Function',
    Properties: { ...defaultProps, ...props },
    LogicalId: props.LogicalId || 'TestFunction'
  };
}
const resource = createResource({ TracingConfig: { Mode: 'Active' } });
const result = rule.evaluate(resource, stackName);

// After
function createTemplate(props: Record<string, any> = {}, logicalId = 'TestFunction'): Template {
  return {
    Resources: {
      [logicalId]: {
        Type: 'AWS::Lambda::Function',
        Properties: { ...defaultProps, ...props }
      }
    }
  };
}
const template = createTemplate({ TracingConfig: { Mode: 'Active' } });
const result = rule.evaluateResource(stackName, template, template.Resources!['TestFunction'] as Resource);
```

#### 4.3 Test Method Calls

Replace `rule.evaluate(resource, stackName)` with `rule.evaluateResource(stackName, template, resource)`.

#### 4.4 Additional Assertions

New-style tests should verify `resourceName` is resolved correctly from the template:
```typescript
expect(result?.resourceName).toBe('TestFunction');
```

#### 4.5 Legacy Stub Test

Add a test confirming the stub method returns null:
```typescript
describe('evaluate (legacy stub)', () => {
  it('should return null', () => {
    const result = rule.evaluate(
      { Type: 'AWS::Lambda::Function', Properties: {}, LogicalId: 'Test' },
      stackName
    );
    expect(result).toBeNull();
  });
});
```

### 5. Verify

After conversion:

1. Run the specific test: `npx vitest run tests/core/scanners/srt/rules/{service}/{###}-{name}.test.ts`
2. Run the TypeScript compiler: `npx tsc --noEmit`
3. Fix any compilation or test failures

### 6. Reference Files

| File | Purpose |
|------|---------|
| `src/assess/scanning/security-matrix/security-rule-base.ts` | BaseRule with both `evaluate` and `evaluateResource` |
| `src/assess/scanning/security-matrix/matrix-scanner-engine.ts` | How rules are dispatched (evaluateResource first, evaluate fallback) |
| `src/assess/scanning/security-matrix/rules/s3/001-access-logging.ts` | Reference new-style rule (cross-resource) |
| `src/assess/scanning/security-matrix/rules/lambda/011-cloudwatch-alarms.ts` | Reference new-style rule (cross-resource with template lookup) |
| `tests/core/scanners/srt/rules/s3/001-access-logging.test.ts` | Reference new-style test |

## Clean Code Requirements

- Extract validation logic into small, focused private methods
- Use early-return guards instead of nested if blocks
- Keep methods under 20 lines
- Use `appliesTo()` or direct type check as the first guard
- No comments explaining what code does — only why, when non-obvious
