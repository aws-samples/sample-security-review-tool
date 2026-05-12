# CloudFormationResolver

The `CloudFormationResolver` is a utility class available to rules that need to resolve intrinsic functions at evaluation time. It is separate from `parseCfnTemplate` — most rules don't need it because `parseCfnTemplate` already resolves intrinsics before the rule runs.

Use the resolver when a rule needs to determine whether a value is a resolvable reference or an opaque intrinsic, and to extract which resources are referenced.

## Constructor

```typescript
new CloudFormationResolver(resources?: CloudFormationResource[])
```

Takes an array of `CloudFormationResource` objects (with `LogicalId`, `Type`, and `Properties`) and builds an internal lookup map.

## resolve<T>(value: any, options?: ResolveOptions): ResolvedValue<T>

Analyzes a value and returns information about whether it can be resolved.

**Return type:**
```typescript
interface ResolvedValue<T> {
  value: T | null;          // the resolved value, or null if unresolvable
  isResolved: boolean;      // true if the value is fully determined
  isIntrinsicFunction: boolean;  // true if the value is/contains an intrinsic function
  referencedResources: string[]; // logical IDs of all resources referenced
}
```

**Resolution behavior by value type:**

| Input | isResolved | value | referencedResources |
|-------|-----------|-------|---------------------|
| Simple string/number/boolean | true | the value itself | [] |
| `{ Ref: "MyResource" }` (resource exists) | true | `"MyResource"` | `["MyResource"]` |
| `{ Ref: "MyResource" }` (resource not in resolver) | false | `"MyResource"` | `["MyResource"]` |
| `{ "Fn::GetAtt": ["Res", "Attr"] }` | false | null | `["Res"]` |
| `{ "Fn::If": [...] }` | false | null | (any nested refs) |
| `{ "Fn::Sub": "..." }` | false | null | (any nested refs) |
| `{ "Fn::ImportValue": "..." }` | false | null | [] |
| Array of values | true only if ALL items resolve | resolved array or null | all nested refs |
| Plain object (not intrinsic) | true only if ALL properties resolve | resolved object or null | all nested refs |

## getResource(logicalId: string): any | null

Returns the resource definition for a given logical ID, or null if not found.

## getResourcesByType(type: string): any[]

Returns all resources matching the given type, each augmented with a `LogicalId` property.

## ResolveOptions

```typescript
interface ResolveOptions {
  treatLiteralStringsAs?: 'external-references';
}
```

When `treatLiteralStringsAs` is `'external-references'`, plain strings are treated as unresolvable external references (value=null, isResolved=false). This is useful when a property could contain either a Ref or a hardcoded ARN, and you want to distinguish "known internal reference" from "unknown external value."

## When to Use the Resolver vs. Direct Property Access

Most rules don't need the resolver because `parseCfnTemplate` has already resolved Ref and GetAtt into strings before the rule runs. The resolver is useful when:

1. A rule needs to know if a value was originally an intrinsic function (to decide whether to flag it)
2. A rule needs to trace which resources are referenced by a property
3. A rule operates on the raw template before preprocessing (uncommon)

For typical rule logic, direct property access on the preprocessed template is sufficient.
