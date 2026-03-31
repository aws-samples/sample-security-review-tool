---
name: security-rule-generator
description: Generates new security matrix rules for CloudFormation/CDK scanning. Use when creating new security checks, implementing AWS best practices rules, or adding service-specific validation rules.
---

# Security Matrix Rule Generator

Generates security matrix rules that scan CloudFormation templates for AWS security best practices violations.

## When to Use

- User asks to create/add a new security rule
- User wants to implement a specific AWS security check
- User provides a security requirement to enforce

## Process

### 1. Gather Requirements

Ask the user for:
- **Rule ID**: Format `SERVICE-###` (e.g., S3-010, KMS-003, EC2-007)
- **Resource types**: AWS CloudFormation resource types to check (e.g., `AWS::S3::Bucket`)
- **Security requirement**: What security property to validate
- **Priority**: HIGH (critical security), MEDIUM (recommended), LOW (best practice)

### 2. Research AWS Documentation

Fetch relevant AWS documentation to understand:

**CloudFormation Resource Properties:**
```
WebFetch: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-{service}-{resource}.html
```

**CDK Construct Documentation:**
```
WebFetch: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_{service}.{Construct}.html
```

### 3. Review Existing Patterns

Read existing rules in the target service folder:
```
src/assess/scanning/security-matrix/rules/{service}/
```

Reference examples:
- Simple rule: [003-dead-letter-queue.ts](src/assess/scanning/security-matrix/rules/sqs/003-dead-letter-queue.ts)
- Complex rule: [002-cmk-least-privilege.ts](src/assess/scanning/security-matrix/rules/kms/002-cmk-least-privilege.ts)

### 4. Generate Rule Implementation

Use the new `evaluateResource` pattern. See [PATTERNS.md](PATTERNS.md) for detailed examples.

**Rule Template:**

```typescript
import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * SERVICE-###: Brief description
 *
 * [Rationale from AWS documentation]
 */
export class Service###Rule extends BaseRule {
    constructor() {
        super(
            'SERVICE-###',
            'HIGH',
            'Issue description shown in findings',
            ['AWS::Service::Resource']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const property = resource.Properties?.PropertyName;

        if (!property) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Fix: Add PropertyName to enable security feature'
            );
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }
}

export default new Service###Rule();
```

### 5. Register the Rule

**Add to service index:**
```typescript
// src/assess/scanning/security-matrix/rules/{service}/index.ts
export { default as Service###Rule } from './###-rule-name.js';
```

**For new services, also update:**
```typescript
// src/assess/scanning/security-matrix/rules/index.ts
import { serviceRules } from './{service}/index.js';
export const allRules = [...existingRules, ...serviceRules];
```

### 6. Generate Unit Tests

Create test file at `tests/core/scanners/srt/rules/{service}/###-rule-name.test.ts`

See [PATTERNS.md](PATTERNS.md#test-patterns) for test templates.

**Required test categories:**
- `appliesTo` - verify resource type matching
- `evaluateResource` - main validation logic
- `evaluate` - legacy method stub returns null

**Test cases to cover:**
- Compliant resources (return null)
- Non-compliant resources (return finding with correct issue/fix)
- Edge cases: empty properties, CloudFormation intrinsic functions (Ref, Fn::GetAtt)
- Rule properties: verify id, priority (avoid checking description - brittle)

## Clean Code Requirements

Rules MUST follow Clean Code principles:

### Naming
- Class: `Service###Rule` (e.g., `Kms002Rule`, `S3010Rule`)
- File: `###-rule-name.ts` (e.g., `002-cmk-least-privilege.ts`)
- Methods: verb phrases describing action (`isOverlyPermissive`, `hasEncryption`)

### Methods
- Extract validation logic into small, focused private methods
- Each method does ONE thing
- Max 20 lines per method (prefer 10)
- 0-2 parameters ideal

### Constants
- Use `private static readonly` for magic values
- Group related constants (e.g., `ALLOWED_ACTIONS`)

### Self-Documenting
- Names should reveal intent
- Comments only for "why", never "what"
- JSDoc only for public API and complex rationale

## Output Checklist

Before completion, verify:
- [ ] Rule uses `evaluateResource` pattern (not legacy `evaluate`)
- [ ] Rule uses `createResult` helper (not legacy `createScanResult`)
- [ ] Class name matches `Service###Rule` format
- [ ] File name matches `###-rule-name.ts` format
- [ ] Rule exported from service index.ts
- [ ] JSDoc explains the security rationale
- [ ] Fix message is actionable and specific
- [ ] Private methods are small and focused
- [ ] Unit test created at `tests/core/scanners/srt/rules/{service}/###-rule-name.test.ts`
- [ ] Tests cover compliant/non-compliant scenarios
- [ ] Edge cases tested (empty props, CloudFormation refs)
