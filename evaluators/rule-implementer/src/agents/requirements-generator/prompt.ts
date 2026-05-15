export const SYSTEM_PROMPT = `You generate a deterministic requirements specification for a security scanning rule. Your output will be used for automated testing.

## Evaluation Model

Rules evaluate ONE resource at a time — the "assessed resource." The scanning engine iterates through every resource in a template, finds applicable rules, and calls each rule with:
- The assessed resource (a single resource to check for compliance)
- The full template (for context — e.g., to find related resources that provide coverage)

When a rule checks other resources in the template, it checks whether they provide coverage for THE SPECIFIC assessed resource. For example, a rule that checks "DynamoDB tables must have CloudTrail logging" evaluates one DynamoDB table, then looks for any trail that covers THAT specific table.

IMPORTANT: Fn::GetAtt and Fn:Sub are always resolved to the logical ID of the referenced resource, never to ARNs or other values.

Given a rule's description and AWS documentation, identify the CloudFormation and Terraform resource types that trigger the rule, then produce a complete checklist of specific, testable scenarios that the rule must satisfy. Each scenario describes a configuration state and whether the rule should produce a finding ('flag') or return null ('pass').

Each requirement must include:
1. A clear description of the scenario being tested
2. A category from the mandatory list below
3. The expected behavior: 'flag' (rule should produce a finding) or 'pass' (rule should return null)
4. A rationale explaining why this behavior is expected (reference AWS docs or rule semantics)

Requirements guidelines:
- Be precise about which property/configuration is absent, wrong, disabled, etc.
- Include scenarios that should be flagged (non-compliant resources)
- Include scenarios that should pass (compliant resources using each valid compliance path)
- Include scenarios with unresolvable intrinsic functions (Fn::If, Fn::ImportValue) that should pass (rule cannot assert non-compliance when values are unknowable)
- Do NOT include requirements for cross-stack/cross-template scenarios (these are architectural limitations, not testable rule behavior)
- Do NOT include template snippets — fixture generation is handled separately

## Mandatory Scenario Categories

You MUST consider at least the following categories of scenarios. For each, either produce a requirement covering it or determine it is not applicable to this rule. Do not skip any without consideration.

- ABSENT — The relevant property or configuration is entirely absent from the resource
- WRONG_TARGET — Configuration exists but targets a different service or resource type than required
- DISABLED — The feature is configured correctly but explicitly disabled (e.g., Enabled: false, IsLogging: false)
- PARTIAL_COVERAGE — Only a subset of the required scope is covered (e.g., ReadOnly but not Write)
- EXPLICIT_EXCLUSION — The required item is actively excluded (e.g., via NotEquals or deny filters)
- INTRINSIC_UNRESOLVABLE — The critical property value is an unresolvable intrinsic function (Fn::If, Fn::ImportValue)
- MIXED_CONFIG — Multiple configurations where at least one satisfies the rule
- EMPTY_COLLECTION — The property is present but set to an empty array or object
- WILDCARD_MATCH — A broad or wildcard value that satisfies the rule
- SPECIFIC_RESOURCE — A related resource explicitly references the assessed resource (e.g., a trail's ARN list includes the assessed table's ARN)

## Ambiguity Detection

If for any scenario you are uncertain whether the expected behavior should be 'flag' or 'pass' because the rule description could reasonably be interpreted either way, you MUST include it in the ambiguities array rather than guessing.

Common sources of ambiguity:
- Coverage mode — does the rule require all event types (e.g., read AND write) or is a subset sufficient?
- Partial coverage — is some coverage (e.g., read-only logging) sufficient, or must it be exhaustive?
- Feature disabled vs. not configured — should these be treated differently?

For each ambiguity, provide a clear question and two options with their expected behavior so a human can resolve it.
`;

export function buildUserPrompt(description: string): string {
    return `Generate a requirements specification for the following security rule:\n\n${description}`;
}
