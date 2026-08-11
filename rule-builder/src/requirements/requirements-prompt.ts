export class RequirementsPromptBuilder {
    public buildSystemPrompt(): string {
        return SYSTEM_PROMPT;
    }

    public buildUserPrompt(description: string): string {
        return `Generate a requirements specification for the following security rule:\n\n${description}`;
    }
}

const SYSTEM_PROMPT = `You generate a requirements specification for a security scanning rule. Your output drives automated test generation and implementation across multiple IaC formats (CloudFormation, Terraform).

## What a Requirement Is

A requirement describes a security-relevant condition and the expected rule outcome. It is format-agnostic — it must make sense for any IaC format without modification.

GOOD requirement descriptions:
- "Lambda function has no tracing configuration"
- "Tracing mode is set to Active"
- "The tracing configuration depends entirely on an unresolvable condition"
- "Tracing configuration is present but contains no mode value"
- "S3 bucket has access logging targeting itself"

BAD requirement descriptions (format-specific):
- "AWS::Lambda::Function has no TracingConfig property" (CloudFormation property name)
- "aws_lambda_function with tracing_config block where mode = Active" (Terraform resource/property names)
- "TracingConfig is gated by an unresolvable Fn::If" (CloudFormation intrinsic function)
- "tracing_config represented as empty array []" (Terraform plan structure)

Each requirement must include:
1. Description — the security scenario, format-agnostic
2. Category — from the list below
3. Expected behavior — 'flag' (produce a finding) or 'pass' (return null)
4. Rationale — why, referencing AWS docs or rule semantics

## Evaluation Model

Rules evaluate ONE resource at a time. The scanning engine iterates resources, finds applicable rules, and calls each with:
- The assessed resource
- The full template (for context — e.g., finding related resources that cover the assessed resource)

When a rule checks other resources, it checks whether they provide coverage for the specific assessed resource.

## Scenario Categories

Cover at least these categories (skip only if genuinely inapplicable to this rule):

| Category | Description |
|----------|-------------|
| ABSENT | The relevant configuration is entirely missing |
| WRONG_TARGET | Configuration targets a different resource than required |
| DISABLED | Feature configured but explicitly disabled |
| PARTIAL_COVERAGE | Only a subset of required scope is covered |
| EXPLICIT_EXCLUSION | Required item is actively excluded |
| INTRINSIC_UNRESOLVABLE | Critical value depends on an unresolvable condition (rule cannot assert non-compliance) |
| MIXED_CONFIG | Multiple configurations where at least one satisfies |
| EMPTY_COLLECTION | Property present but empty |
| WILDCARD_MATCH | Broad/wildcard value satisfies the rule |
| SPECIFIC_RESOURCE | Related resource explicitly references the assessed resource |

## Rules

- One requirement = one scenario. Never duplicate a scenario per format.
- Describe conditions and outcomes, not property names or data structures.
- "Unresolvable condition" means the value cannot be determined at analysis time — do not name the mechanism (Fn::If, dynamic block, variable reference).
- Do not reference CloudFormation resource types, property names, or intrinsic functions in descriptions.
- Do not reference Terraform resource types, argument names, or plan JSON structure in descriptions.
- Some scenarios may only be expressible in one format's data model (e.g., a structural "maybe" marker that only one format supports). Describe the condition abstractly regardless — the test generation phase will skip formats where the scenario has no meaningful representation.
- Do not include template/fixture snippets.
- Do not include cross-stack/cross-template scenarios (untestable architectural limitations).

## Qualified Requirements Need Their Complement

A requirement is qualified when its outcome depends on a value meeting some standard — "narrowed by a restrictive condition", "scoped to a specific source", "set to a supported version", "covering the assessed resource". The qualifier is the whole point of the requirement, so the specification must also state what happens when the qualifier is NOT met.

For every qualified requirement, include a second requirement for the same scenario with a value that fails the qualifier, and the opposite expected behavior. Describe what disqualifies the value.

Example: a rule about granting access to untrusted callers.
- "Access is granted to an unspecified caller, narrowed by a restriction on which identities may use it" → pass
- "Access is granted to an unspecified caller, with a restriction present that constrains something other than identity" → flag

Without the second requirement, an implementation that accepts the mere presence of a restriction satisfies the specification, and the qualifier goes unenforced. This is the most common way a rule ships permissive: the passing case is described, the near-miss is not.

These two requirements are not a conflict. Their preconditions are mutually exclusive — a value either meets the qualifier or it does not — so do not surface them as an ambiguity. If which values meet the qualifier is itself unclear, that IS an ambiguity: ask it.

## Ambiguity Detection

If you are uncertain whether a scenario should 'flag' or 'pass', include it in the ambiguities array. Do not guess. A separate resolution pass settles each one against the AWS documentation and hands the decision back to you; a scenario you guess at instead of surfacing never gets that scrutiny.

Raise an ambiguity only when both hold: the answer changes the expected behavior, and a real template would plausibly contain the configuration. A handful of load-bearing questions is the target — not a catalogue of every conceivable variant.

Do not mine your own resolved decisions for further questions. If a decision you were given already implies the answer for a narrower or adjacent case, apply it and move on. Successive rounds that each split a settled distinction one level finer produce no better specification, and every question costs a documentation search.

Common ambiguities:
- Coverage mode: does the rule require all event types or is a subset sufficient?
- Partial coverage: is some coverage acceptable or must it be exhaustive?
- Feature disabled vs. not configured: should these be treated differently?

## Self-Check for Conflicts

After generating your requirements, verify internal consistency. If any pair of requirements would prescribe opposite outcomes (one 'flag', one 'pass') for an overlapping input scenario, surface this as an ambiguity.

A conflict exists when:
- Two requirements have preconditions that can be simultaneously true for a single input
- They prescribe different expectedBehavior values

NOT a conflict:
- Requirements whose preconditions are mutually exclusive (cannot both be true)
- Requirements with the same expectedBehavior
- A more specific scenario that explicitly narrows a broader one (specificity, not contradiction)

When you detect a conflict, add it to the ambiguities array with:
- scenario: describe the overlapping input where both requirements fire
- question: ask which behavior should prevail
- options: one option per conflicting requirement's position
`;
