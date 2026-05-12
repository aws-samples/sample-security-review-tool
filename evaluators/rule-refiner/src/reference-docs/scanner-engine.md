# Scanner Engine

The `SecurityMatrixScannerEngine` orchestrates rule evaluation against CloudFormation templates and Terraform plans.

## CloudFormation Scanning Flow

```
Template file (.yaml/.json)
    │
    ▼
readCfnFile(filePath)          → parses YAML/JSON into a Template object
    │
    ▼
parseCfnTemplate(template)     → resolves Ref, GetAtt, Sub, FindInMap, pseudo-params
    │
    ▼
For each resource in template.Resources:
    │
    ├─ Filter rules where rule.appliesTo(resource.Type) === true
    ├─ Sort matching rules by ID (alphabetical)
    │
    └─ For each matching rule:
        │
        ├─ Call rule.evaluateResource(stackName, template, resource)
        │
        ├─ If result is undefined → fallback to legacy rule.evaluate(...)
        │
        └─ If result is not null → collect as a finding
```

## What the Rule Receives

After preprocessing, the rule's `evaluateResource` method receives:

- `stackName` — the template file path relative to the project root
- `template` — the full template with all Ref/GetAtt/Sub/FindInMap resolved. Only `Fn::If` and `Fn::ImportValue` remain as objects. Everything else is a plain value (string, number, boolean, array, or object).
- `resource` — one entry from `template.Resources`. This is the same object reference (not a copy). Its `Properties` contain the resolved values.

## Terraform Scanning Flow

```
Terraform plan JSON
    │
    ▼
readTerraformPlan(planJsonPath)  → extracts TerraformResource array
    │
    ▼
For each resource:
    │
    ├─ Filter rules where rule.appliesTo(resource.type) === true
    ├─ Sort matching rules by ID
    │
    └─ For each matching rule:
        │
        └─ Call rule.evaluate(resource, projectName, allResources)
```

## Key Facts for Rule Authors

1. Rules are called once per matching resource — not once per template.
2. The template is fully preprocessed before any rule runs. Rules see resolved values, not intrinsic function objects (except Fn::If and Fn::ImportValue).
3. `resource` is the same object as `template.Resources[logicalId]`. Object identity (`===`) is used by `createResult` to find the logical ID.
4. If a rule throws an error, the scanner catches it, logs it, and continues evaluating other rules. One broken rule doesn't stop the scan.
5. Rules are sorted by ID before evaluation. This is just for deterministic output ordering — it doesn't affect rule logic.
6. The scanner loads ALL rules at startup from `allCloudFormationRules` and `allTerraformRules` arrays.
