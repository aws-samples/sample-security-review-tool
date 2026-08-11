import z from 'zod';

export const RequirementCategorySchema = z.enum([
    'ABSENT', 'WRONG_TARGET', 'DISABLED', 'PARTIAL_COVERAGE',
    'EXPLICIT_EXCLUSION', 'INTRINSIC_UNRESOLVABLE', 'MIXED_CONFIG',
    'EMPTY_COLLECTION', 'WILDCARD_MATCH', 'SPECIFIC_RESOURCE',
]);

const REQUIREMENT_FIELDS = {
    id: z.string().describe('Requirement identifier (e.g., REQ-01)'),
    description: z.string().describe('Format-agnostic scenario description — no IaC property names, resource types, or intrinsic functions'),
    category: RequirementCategorySchema.describe('Scenario category from the mandatory list'),
};

const DecidedRequirementSchema = z.object({
    ...REQUIREMENT_FIELDS,
    expectedBehavior: z.enum(['flag', 'pass']).describe('Whether the rule should fire (flag) or not (pass)'),
    rationale: z.string().describe('Why this expected behavior is correct, referencing AWS docs or rule semantics'),
    ambiguity: z.null().describe('Null, because this requirement is decided'),
});

const OpenRequirementSchema = z.object({
    ...REQUIREMENT_FIELDS,
    expectedBehavior: z.null().describe('Null, because you could not decide — the question goes in ambiguity'),
    rationale: z.null().describe('Null, because the reason comes from settling the ambiguity'),
    ambiguity: z.string().describe('The one question that must be answered before this scenario has an expected behavior'),
});

// The union is the constraint: a requirement carries a decision or a question, never both and never
// neither. It reaches the model as the two permitted shapes, so nothing downstream has to re-check it.
export const DraftRequirementSchema = z.union([DecidedRequirementSchema, OpenRequirementSchema]);

export const AmbiguityResolutionSchema = z.object({
    chosenBehavior: z.enum(['flag', 'pass']).describe('The resolved expected behavior for the ambiguous scenario'),
    summary: z.string().describe('The reason for the decision in one sentence, readable on its own'),
    rationale: z.string().describe('Why this behavior is correct — cite what the documentation says, or state that none was found and the default applies'),
    docReference: z.string().nullable().describe('URL of the AWS documentation that settles the question, or null when none was found'),
    settledBy: z.enum(['documentation', 'strict-default', 'intrinsic-exception']).describe('documentation when a cited doc decides it, strict-default when no doc settles it, intrinsic-exception when the value is unresolvable at analysis time'),
});

export const RequirementsOutputSchema = z.object({
    requirements: z.array(DraftRequirementSchema).min(1).describe('Complete requirements specification, one entry per scenario'),
    cfnResources: z.array(z.string()).describe('List of CloudFormation resource types that trigger the rule'),
    tfResources: z.array(z.string()).describe('List of Terraform resource types that trigger the rule'),
});
