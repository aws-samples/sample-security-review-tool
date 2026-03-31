# Security Rule Debugging Guide

Reference for common false positive patterns and debugging techniques.

## Common False Positive Causes

### 1. Unrecognized Intrinsic Functions

Rules often check for string patterns but fail when values are CloudFormation intrinsic functions.

**Problem Pattern:**
```typescript
// Rule checks string content
if (typeof valueFrom === 'string' && !valueFrom.includes('secretsmanager')) {
  return finding; // False positive when valueFrom is an object
}
```

**Affected Intrinsics:**
- `Fn::ImportValue` - Cross-stack references
- `Fn::If` - Conditional values
- `Fn::Select` - Array selection
- `Fn::GetAtt` - Resource attribute references

**Fix Pattern:**
```typescript
// Check object type first, then handle intrinsics
if (typeof valueFrom === 'object' && hasIntrinsicFunction(valueFrom)) {
  // Handle intrinsic function case
} else if (typeof valueFrom === 'string') {
  // Handle string case
}
```

### 2. Cross-Stack References (Fn::ImportValue)

`Fn::ImportValue` is inherently opaque - the import name doesn't reveal what type of resource it references.

**Example:**
```json
{
  "ValueFrom": {
    "Fn::ImportValue": "mystack:ExportsOutputRefMySecret12345"
  }
}
```

The string `ExportsOutputRefMySecret12345` doesn't contain `secretsmanager` even though it references a Secrets Manager secret.

**Fix Options:**

Option A - Trust cross-stack imports:
```typescript
// Cross-stack imports typically reference secure values
if (valueFrom['Fn::ImportValue']) {
  return null; // Trust the source stack's security
}
```

Option B - Add import patterns:
```typescript
const validPatterns = [
  /secretsmanager/i,
  /ssm/i,
  /Fn::ImportValue/i,  // Add this
  /ImportValue/i,       // Add this
];
```

### 3. CDK Token Patterns

CDK generates tokens that don't contain recognizable service names.

**Example:**
```json
{
  "Value": "${Token[TOKEN.123]}"
}
```

**Common CDK Patterns to Recognize:**
```typescript
const cdkPatterns = [
  /Token\[/i,
  /\$\{Token/i,
  /fromSecretName/i,
  /fromSecretArn/i,
  /fromSecretAttributes/i,
  /StringParameter\.valueForSecureStringParameter/i,
  /Secret\.fromSecretCompleteArn/i,
];
```

### 4. Dynamic References

AWS CloudFormation dynamic references have special syntax.

**Formats:**
```
{{resolve:secretsmanager:MySecret:SecretString:password}}
{{resolve:ssm:MyParameter}}
{{resolve:ssm-secure:MySecureParameter}}
```

**Detection:**
```typescript
if (typeof value === 'string' && value.startsWith('{{resolve:')) {
  // This is a dynamic reference - check the service
  if (value.includes('secretsmanager') || value.includes('ssm-secure')) {
    return null; // Valid secure reference
  }
}
```

### 5. Nested Intrinsic Functions

Rules may not handle deeply nested intrinsics.

**Example:**
```json
{
  "Value": {
    "Fn::If": [
      "UseProduction",
      {"Fn::ImportValue": "prod-secret"},
      {"Fn::ImportValue": "dev-secret"}
    ]
  }
}
```

**Fix Pattern:**
```typescript
// Recursively check all branches of Fn::If
if (value['Fn::If'] && Array.isArray(value['Fn::If'])) {
  const [condition, trueValue, falseValue] = value['Fn::If'];
  // Check both branches
  const trueValid = this.isValidSecretReference(trueValue);
  const falseValid = this.isValidSecretReference(falseValue);
  if (trueValid && falseValid) {
    return null;
  }
}
```

### 6. Fn::Join Constructing ARNs

Rules may not recognize ARNs being constructed via `Fn::Join`.

**Example:**
```json
{
  "Value": {
    "Fn::Join": ["", [
      "arn:aws:secretsmanager:",
      {"Ref": "AWS::Region"},
      ":",
      {"Ref": "AWS::AccountId"},
      ":secret:MySecret"
    ]]
  }
}
```

**Detection:**
```typescript
if (value['Fn::Join']) {
  const joinStr = JSON.stringify(value['Fn::Join']);
  if (joinStr.includes('secretsmanager') || joinStr.includes('ssm')) {
    return null; // Constructing a valid ARN
  }
}
```

## Debugging Techniques

### 1. Stringify and Search

When checking intrinsic functions, stringify the entire object:

```typescript
const valueStr = JSON.stringify(value);
if (/secretsmanager/i.test(valueStr)) {
  // Pattern found somewhere in the structure
}
```

### 2. Check Type Before Content

Always check the type of a value before checking its content:

```typescript
// Bad - crashes on objects
if (value.includes('secret')) { ... }

// Good - type-safe
if (typeof value === 'string' && value.includes('secret')) { ... }
```

### 3. Use Utility Functions

Leverage the existing utilities in `cloudformation-intrinsic-utils.ts`:

```typescript
import { hasIntrinsicFunction, containsPattern, extractResourceIdsFromReference } from '../utils/cloudformation-intrinsic-utils.js';

// Check for any intrinsic function
if (hasIntrinsicFunction(value)) {
  // Handle intrinsic
}

// Check for pattern in stringified value
if (containsPattern(value, /secretsmanager/i)) {
  // Pattern found
}

// Extract referenced resource IDs
const refs = extractResourceIdsFromReference(value);
```

### 4. Trace with Console Output

When debugging locally, add temporary logging:

```typescript
console.log('Checking value:', JSON.stringify(value, null, 2));
console.log('hasIntrinsicFunction:', hasIntrinsicFunction(value));
console.log('containsPattern(secretsmanager):', containsPattern(value, /secretsmanager/i));
```

## Rule-Specific Notes

### ECS-002: Sensitive Parameters

**Known False Positive:** `Fn::ImportValue` referencing Secrets Manager

The rule checks `Secrets[].ValueFrom` for patterns like `secretsmanager` or `ssm`. When the secret is imported from another stack, the import name doesn't contain these patterns.

**Fix:** Add `Fn::ImportValue` to trusted patterns or add explicit check:
```typescript
// Trust cross-stack secret imports
if (valueFrom['Fn::ImportValue']) {
  isValid = true;
}
```

### Pattern Validation Checklist

When reviewing a rule for false positive potential, verify:

- [ ] Handles both string and object values
- [ ] Checks `hasIntrinsicFunction()` before string operations
- [ ] Uses `containsPattern()` for pattern matching in intrinsics
- [ ] Handles `Fn::ImportValue` cross-stack references
- [ ] Handles `Fn::If` conditional values
- [ ] Handles `Fn::Join` constructed ARNs
- [ ] Handles CDK token patterns
- [ ] Handles dynamic references (`{{resolve:...}}`)
