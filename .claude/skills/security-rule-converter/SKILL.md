---
name: security-rule-converter
description: Converts old-style security matrix rules (using evaluate/createScanResult) to the new evaluateResource/createResult pattern. Use when migrating existing rules to the new implementation style. Specify a rule ID like LAMBDA-004 or S3-002.
---

# Security Rule Converter

Converts legacy security matrix rules from the old `evaluate`/`createScanResult` pattern to the new `evaluateResource`/`createResult` pattern.

## When to Use

- User asks to convert/migrate/update a security rule to the new pattern
- User provides a rule ID (e.g., LAMBDA-004, EKS-001, DDB-002) to convert
- User wants to modernize a rule implementation

## Process

### 1. Locate the Rule

Parse the rule ID. Format is `SERVICE-###` (e.g., LAMBDA-004, S3-002, DDB-002).

Map service prefix to folder name:

```
LAMBDA -> lambda/          S3 -> s3/              EC2 -> ec2/
EKS -> eks/                ECS -> ecs/            IAM -> iam/
KMS -> kms/                RDS -> rds/            API-GW -> api-gateway/
DDB -> dynamodb/           VPC -> vpc/            SNS -> sns/
SQS -> sqs/                CF -> cloudfront/      ELB -> elastic-load-balancing/
ECR -> ecr/                EFS -> efs/            FSX -> fsx/
IOT -> iot/                LEX -> lex/            COGNITO -> cognito/
REDSHIFT -> redshift/      OPENSEARCH -> opensearch/
ELASTICACHE -> elasticache/ DOCUMENTDB -> documentdb/
CODEBUILD -> codebuild/    STEP-FN -> step-functions/
```

Find the rule and test files:
```
Rule: src/assess/scanning/security-matrix/rules/{service}/*{number}*.cf.ts
Test: tests/core/scanners/srt/rules/{service}/*{number}*.test.ts
```

Read both files before proceeding.

### 2. Analyze Complexity

Determine the category by inspecting the existing `evaluate` method:

**Simple** — Only inspects `resource.Properties` on the current resource. No `allResources` usage, no `CloudFormationResolver` import.

**Cross-resource** — Uses `allResources` to find related resources (e.g., checking if a CloudWatch alarm exists for a Lambda). Look for: `allResources?.some(`, `allResources?.find(`, `allResources?.filter(`, or iteration over `allResources`.

**Resolver-dependent** — Imports `CloudFormationResolver` from `'../../resolver.js'`. Uses `resolver.resolve()` to handle intrinsic functions.

### 3. Convert the Rule

#### 3.1 Imports

```typescript
// Before
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

// After
import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';
```

Keep `CloudFormationResolver` import if still needed (see 3.5).

#### 3.2 New Entry Point

Move logic from `evaluate` into `evaluateResource`:

```typescript
// New entry point
public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
  if (!this.appliesTo(resource.Type)) return null;
  // ... converted logic
  return null;
}

// Legacy stub
public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
  return null;
}
```

Use early-return type guard as the first line. Prefer `if (!this.appliesTo(resource.Type)) return null;` or `if (resource.Type !== 'AWS::...') return null;`.

#### 3.3 Result Creation

Replace `createScanResult` with `createResult`. Note the parameter order change and that `fix` is **required**:

```typescript
// Before (fix is optional)
this.createScanResult(resource, stackName, issue, fix)

// After (fix is required, template is added)
this.createResult(stackName, template, resource, issue, fix)
```

#### 3.4 Cross-Resource References

Replace `allResources` array lookups with `template.Resources` object iteration:

```typescript
// Before
allResources?.some(r => r.Type === 'AWS::CloudTrail::Trail' && this.checkTrail(r))

// After
Object.entries(template.Resources || {}).some(([id, r]) =>
  r.Type === 'AWS::CloudTrail::Trail' && this.checkTrail(r)
)
```

Key difference: In old pattern, each item is `CloudFormationResource` (has `.LogicalId`). In new pattern, each entry is `[logicalId: string, resource: Resource]` — the logical ID is the key, not a property.

Update helper methods that accepted `CloudFormationResource` to accept `Resource` instead. If they only used `.Properties` and `.Type`, the change is minimal.

#### 3.5 CloudFormationResolver Handling

For rules that use `CloudFormationResolver`:

**Strategy A — Inline intrinsic handling** (preferred for simple checks):
```typescript
private isUnresolvableIntrinsic(value: any): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 1) return false;
  return keys[0] === 'Ref' || keys[0].startsWith('Fn::');
}
```

**Strategy B — Construct resolver from template** (when `resolver.resolve()` is genuinely needed):
```typescript
private buildResolver(template: Template): CloudFormationResolver {
  const cfResources = Object.entries(template.Resources || {}).map(([id, res]) => ({
    Type: res.Type,
    Properties: res.Properties || {},
    LogicalId: id
  }));
  return new CloudFormationResolver(cfResources);
}
```

Then call `this.buildResolver(template)` instead of `new CloudFormationResolver(allResources)`.

#### 3.6 Logical ID Access

When the rule needs its own logical ID from the template:

```typescript
private getLogicalId(template: Template, resource: Resource): string {
  if (!template.Resources) return '';
  const entry = Object.entries(template.Resources).find(([_, res]) => res === resource);
  return entry ? entry[0] : '';
}
```

#### 3.7 Do NOT Modify JSDoc

Leave all existing JSDoc comments unchanged. Do not update, rewrite, or remove them.

### 4. Convert the Tests

#### 4.1 Imports

```typescript
// Before
import { RuleClass } from '../../../../../../src/assess/scanning/security-matrix/rules/{service}/{NNN}-{name}.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

// After
import { RuleClass } from '../../../../../../src/assess/scanning/security-matrix/rules/{service}/{NNN}-{name}.cf.js';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';
```

Note: rule imports use `.cf.js` extension (TypeScript compiles `.cf.ts` to `.cf.js`).

#### 4.2 Test Helper Functions

```typescript
// Before
function createResource(props: Record<string, any> = {}): CloudFormationResource {
  return { Type: 'AWS::Lambda::Function', Properties: { ...defaults, ...props }, LogicalId: 'TestFunction' };
}

// After
function createTemplate(props: Record<string, any> = {}, logicalId = 'TestFunction'): Template {
  return {
    Resources: {
      [logicalId]: { Type: 'AWS::Lambda::Function', Properties: { ...defaults, ...props } }
    }
  };
}
```

For cross-resource tests, include all needed resources in the template:
```typescript
function createTemplateWithTrail(tableProps = {}, trailProps = {}): Template {
  return {
    Resources: {
      TestTable: { Type: 'AWS::DynamoDB::Table', Properties: { ...tableDefaults, ...tableProps } },
      TestTrail: { Type: 'AWS::CloudTrail::Trail', Properties: { ...trailDefaults, ...trailProps } }
    }
  };
}
```

#### 4.3 Test Assertions

```typescript
// Before
const result = rule.evaluate(resource, stackName, allResources);

// After
const template = createTemplate({ ... });
const result = rule.evaluateResource(stackName, template, template.Resources!['TestFunction'] as Resource);
expect(result?.resourceName).toBe('TestFunction');
```

#### 4.4 Legacy Stub Test (required)

Add this test block:
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

Run an iterative verification loop until both pass:

```
1. npx tsc --noEmit
   → If type errors: fix and re-run
2. npx vitest run tests/core/scanners/srt/rules/{service}/{NNN}-{name}.test.ts
   → If test failures: fix and re-run
3. Repeat until both pass cleanly
```

### 6. Clean Code Requirements

- Extract validation logic into small, focused private methods
- Use early-return guards instead of nested if blocks
- Keep methods under 20 lines
- Use `appliesTo()` or direct type check as the first guard
- No comments explaining what code does — only why, when non-obvious
- Do NOT modify existing JSDoc comments

### 7. Reference Files

| File | Purpose |
|------|---------|
| `src/assess/scanning/security-matrix/security-rule-base.ts` | BaseRule with both `evaluate` and `evaluateResource` |
| `src/assess/scanning/security-matrix/matrix-scanner-engine.ts` | Dispatcher: evaluateResource first, evaluate fallback |
| `src/assess/scanning/security-matrix/resolver.ts` | CloudFormationResolver for intrinsic resolution |
| `src/assess/scanning/security-matrix/rules/s3/001-access-logging.cf.ts` | Reference: cross-resource new-style rule |
| `src/assess/scanning/security-matrix/rules/lambda/011-cloudwatch-alarms.cf.ts` | Reference: cross-resource new-style rule with template lookup |
| `tests/core/scanners/srt/rules/s3/001-access-logging.test.ts` | Reference: new-style test |
