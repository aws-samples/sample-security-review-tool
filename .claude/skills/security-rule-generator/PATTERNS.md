# Security Rule Patterns

Reference patterns for implementing security matrix rules.

## Imports

```typescript
import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';
```

For complex rules needing CloudFormation intrinsic function resolution:
```typescript
import { CloudFormationResolver } from '../../resolver.js';
```

## Pattern 1: Simple Property Check

Check if a required property exists or has correct value.

```typescript
export class S3010Rule extends BaseRule {
    constructor() {
        super('S3-010', 'HIGH', 'S3 bucket versioning not enabled', ['AWS::S3::Bucket']);
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const versioningConfig = resource.Properties?.VersioningConfiguration;
        const status = versioningConfig?.Status;

        if (status !== 'Enabled') {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Add VersioningConfiguration with Status: "Enabled"'
            );
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }
}
```

## Pattern 2: Policy Statement Analysis

Check IAM/resource policies for overly permissive statements.

```typescript
export class Kms002Rule extends BaseRule {
    private static readonly ALLOWED_WILDCARDS = new Set(['kms:GenerateDataKey*', 'kms:ReEncrypt*']);

    constructor() {
        super('KMS-002', 'HIGH', 'KMS key policy grants overly permissive access', ['AWS::KMS::Key']);
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const statements = this.extractStatements(resource);

        for (const statement of statements) {
            if (this.isOverlyPermissive(statement)) {
                return this.createResult(stackName, template, resource, this.description, this.buildFix(statement));
            }
        }

        return null;
    }

    private extractStatements(resource: Resource): any[] {
        const policy = resource.Properties?.KeyPolicy;
        if (!policy?.Statement) return [];
        return Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
    }

    private isOverlyPermissive(statement: any): boolean {
        if (statement.Effect !== 'Allow') return false;

        const actions = this.normalizeToArray(statement.Action);
        return actions.some(action => this.isDangerousWildcard(action));
    }

    private isDangerousWildcard(action: string): boolean {
        if (typeof action !== 'string' || !action.includes('*')) return false;
        return !Kms002Rule.ALLOWED_WILDCARDS.has(action);
    }

    private normalizeToArray(value: any): any[] {
        return Array.isArray(value) ? value : [value];
    }

    private buildFix(statement: any): string {
        return 'Replace wildcard actions with specific KMS actions based on use case';
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }
}
```

## Pattern 3: Cross-Resource Relationships

When validation requires checking related resources, use the legacy `evaluate` method.

```typescript
export class Vpc007Rule extends BaseRule {
    constructor() {
        super('NET-VPC-007', 'HIGH', 'VPC does not have flow logs enabled', ['AWS::EC2::VPC']);
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        return undefined; // Signal to use legacy evaluate
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!allResources || resource.Type !== 'AWS::EC2::VPC') return null;

        const resolver = new CloudFormationResolver(allResources);
        const hasFlowLog = this.vpcHasFlowLog(resource.LogicalId, allResources, resolver);

        if (!hasFlowLog) {
            return this.createScanResult(resource, stackName, this.description, 'Create AWS::EC2::FlowLog for this VPC');
        }

        return null;
    }

    private vpcHasFlowLog(vpcId: string, resources: CloudFormationResource[], resolver: CloudFormationResolver): boolean {
        return resources.some(r => {
            if (r.Type !== 'AWS::EC2::FlowLog') return false;

            const resourceId = resolver.resolve(r.Properties?.ResourceId);
            return resourceId.referencedResources.includes(vpcId);
        });
    }
}
```

## Pattern 4: Encryption Validation

Common pattern for checking encryption configuration.

```typescript
export class Rds005Rule extends BaseRule {
    constructor() {
        super('RDS-005', 'HIGH', 'RDS instance not encrypted at rest', ['AWS::RDS::DBInstance']);
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const storageEncrypted = resource.Properties?.StorageEncrypted;

        if (storageEncrypted !== true) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Set StorageEncrypted: true and optionally specify KmsKeyId for customer-managed key'
            );
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }
}
```

## CloudFormation Resolver

For handling intrinsic functions (Ref, Fn::GetAtt, Fn::Sub, etc.):

```typescript
const resolver = new CloudFormationResolver(allResources);

const resolved = resolver.resolve(resource.Properties?.VpcId);

if (resolved.isResolved) {
    // Value is a literal, safe to compare
    const vpcId = resolved.value;
} else {
    // Value uses intrinsic functions
    // Check referencedResources for related logical IDs
    const references = resolved.referencedResources; // string[]
}
```

## Common Validations

### Check for public CIDR
```typescript
private isPublicCidr(cidr: any): boolean {
    return cidr === '0.0.0.0/0' || cidr === '::/0';
}
```

### Check for wildcard principal
```typescript
private hasWildcardPrincipal(principal: any): boolean {
    if (principal === '*') return true;
    if (principal?.AWS === '*') return true;
    if (Array.isArray(principal?.AWS)) {
        return principal.AWS.includes('*');
    }
    return false;
}
```

### Normalize array values
```typescript
private normalizeToArray<T>(value: T | T[]): T[] {
    return Array.isArray(value) ? value : [value];
}
```

## File Structure

```
src/assess/scanning/security-matrix/
├── security-rule-base.ts      # BaseRule class
├── resolver.ts                # CloudFormationResolver
├── rules/
│   ├── index.ts               # All rules export
│   └── {service}/
│       ├── index.ts           # Service rules export
│       └── ###-rule-name.ts   # Individual rule
```

## Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| File | `###-kebab-case.ts` | `002-cmk-least-privilege.ts` |
| Class | `Service###Rule` | `Kms002Rule` |
| Rule ID | `SERVICE-###` | `KMS-002` |
| Private method | `camelCase` verb phrase | `isOverlyPermissive` |
| Constants | `SCREAMING_SNAKE_CASE` | `ALLOWED_WILDCARDS` |

## Test Patterns

### Test Imports

```typescript
import { describe, it, expect } from 'vitest';
import { Service###Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/{service}/###-rule-name.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';
```

### Basic Test Structure

```typescript
describe('Service###Rule', () => {
  const rule = new Service###Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::Service::Resource type', () => {
      expect(rule.appliesTo('AWS::Service::Resource')).toBe(true);
    });

    it('should not apply to other resource types', () => {
      expect(rule.appliesTo('AWS::Other::Resource')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    it('should return null for compliant resource', () => {
      const template: Template = {
        Resources: {
          TestResource: {
            Type: 'AWS::Service::Resource',
            Properties: { /* compliant config */ }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestResource'] as Resource);
      expect(result).toBeNull();
    });

    it('should return finding for non-compliant resource', () => {
      const template: Template = {
        Resources: {
          TestResource: {
            Type: 'AWS::Service::Resource',
            Properties: { /* non-compliant config */ }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestResource'] as Resource);
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Service::Resource');
      expect(result?.resourceName).toBe('TestResource');
    });

    it('should return null for non-applicable resource types', () => {
      const template: Template = {
        Resources: {
          OtherResource: { Type: 'AWS::Other::Resource', Properties: {} }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['OtherResource'] as Resource);
      expect(result).toBeNull();
    });

    it('should handle empty properties', () => {
      const template: Template = {
        Resources: {
          TestResource: { Type: 'AWS::Service::Resource', Properties: {} }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestResource'] as Resource);
      // Assert based on rule behavior with empty props
    });

    it('should handle CloudFormation intrinsic functions', () => {
      const template: Template = {
        Resources: {
          TestResource: {
            Type: 'AWS::Service::Resource',
            Properties: {
              SomeProperty: { Ref: 'OtherResource' }
            }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestResource'] as Resource);
      // Assert based on rule behavior with refs
    });
  });

  describe('evaluate', () => {
    it('should return null (stub method)', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::Service::Resource',
        Properties: {},
        LogicalId: 'TestResource'
      };

      expect(rule.evaluate(resource, stackName)).toBeNull();
    });
  });

  describe('rule properties', () => {
    it('should have correct id and priority', () => {
      expect(rule.id).toBe('SERVICE-###');
      expect(rule.priority).toBe('HIGH');
    });
  });
});
```

### Common Assertions

```typescript
// Compliant - no finding
expect(result).toBeNull();

// Non-compliant - has finding
expect(result).not.toBeNull();
expect(result?.resourceType).toBe('AWS::Service::Resource');
expect(result?.resourceName).toBe('TestResource');

// Verify fix message contains key guidance
expect(result?.fix).toContain('expected text');
```

### CloudFormation Intrinsic Function Test Cases

```typescript
// Ref
{ PropertyName: { Ref: 'LogicalResourceId' } }

// Fn::GetAtt
{ PropertyName: { 'Fn::GetAtt': ['ResourceId', 'Attribute'] } }

// Fn::Sub
{ PropertyName: { 'Fn::Sub': '${ResourceId}' } }

// Fn::Join
{ PropertyName: { 'Fn::Join': ['-', ['prefix', { Ref: 'ResourceId' }]] } }
```
