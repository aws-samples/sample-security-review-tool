# BaseRule API

All security rules extend `BaseRule`. This document covers the API that rule implementations use.

## Constructor

```typescript
constructor(id: string, priority: 'HIGH' | 'MEDIUM' | 'LOW', description: string, applicableResourceTypes: string[])
```

- `id` — rule identifier like `"S3-001"` or `"LAMBDA-004"`
- `priority` — severity level
- `description` — human-readable description of what the rule checks
- `applicableResourceTypes` — array of AWS resource types this rule applies to (e.g., `["AWS::S3::Bucket"]`)

## appliesTo(resourceType: string): boolean

Returns true if the rule should be evaluated for a resource of the given type. The scanner calls this to filter rules before evaluation.

## evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null | undefined

The primary evaluation method for new rules. Called once per matching resource in the template.

**Parameters:**
- `stackName` — relative path to the template file (e.g., `"infra/template.yaml"`)
- `template` — the full CloudFormation template (already preprocessed by `parseCfnTemplate`). Access other resources via `template.Resources`
- `resource` — the specific resource being evaluated. This is `template.Resources[logicalId]` — the same object, not a copy

**Returns:**
- `ScanResult` — a finding (the rule detected a violation)
- `null` — no finding (the resource is compliant)
- `undefined` — this rule hasn't implemented `evaluateResource` (triggers fallback to legacy `evaluate`)

**The `resource` object shape:**
```typescript
{
  Type: string;           // e.g., "AWS::S3::Bucket"
  Properties: {           // resource configuration (may be undefined)
    [key: string]: any;
  };
  Metadata?: {            // optional metadata (CDK path lives here)
    "aws:cdk:path"?: string;
  };
}
```

## createResult(stackName: string, template: Template, resource: Resource, issue: string, fix: string): ScanResult

Creates a finding. Call this when the rule detects a violation.

**Parameters:**
- `stackName` — pass through from `evaluateResource`
- `template` — pass through from `evaluateResource`
- `resource` — the resource that has the violation (must be the same object reference from `template.Resources`)
- `issue` — description of what's wrong (e.g., `"S3 bucket does not have server-side encryption enabled"`)
- `fix` — guidance for how to fix the issue (e.g., `"Enable SSE-S3 or SSE-KMS encryption on the bucket by setting the BucketEncryption property"`)

**How it finds the resource name:** It searches `template.Resources` for a key whose value `===` the resource parameter (object identity comparison). This is why `resource` must be the same object reference, not a copy.

**Returns a ScanResult:**
```typescript
{
  source: 'security-matrix',
  path: stackName,
  resourceType: resource.Type,
  resourceName: logicalId,     // found via object identity lookup
  issue: issue,
  fix: fix,
  priority: this.priority,
  check_id: this.id,
  status: 'Open',
  cdkPath: resource.Metadata?.['aws:cdk:path'],
  isCustomResource: boolean    // auto-detected from CDK path
}
```

## Cross-Resource Patterns

Rules often need to inspect resources other than the one being evaluated. Common patterns:

**Find all resources of a type:**
```typescript
const trails = Object.entries(template.Resources || {})
  .filter(([_, r]) => r.Type === 'AWS::CloudTrail::Trail');
```

**Check if a resource references the current one:**
```typescript
const logicalId = Object.keys(template.Resources!)
  .find(key => template.Resources![key] === resource)!;

// After preprocessing, Ref/GetAtt resolve to logical ID strings
const referencesMe = someProperty === logicalId;
```

**Get logical ID of the current resource:**
```typescript
const myLogicalId = Object.keys(template.Resources!)
  .find(key => template.Resources![key] === resource);
```

## Legacy API (do not use in new rules)

- `evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[])` — old evaluation method
- `createScanResult(resource: CloudFormationResource, stackName: string, issue: string, fix?: string)` — old result creation

These exist for backward compatibility. The scanner falls back to `evaluate` only when `evaluateResource` returns `undefined`.
