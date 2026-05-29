import z from 'zod';

export const RequirementCategorySchema = z.enum([
    'ABSENT', 'WRONG_TARGET', 'DISABLED', 'PARTIAL_COVERAGE',
    'EXPLICIT_EXCLUSION', 'INTRINSIC_UNRESOLVABLE', 'MIXED_CONFIG',
    'EMPTY_COLLECTION', 'WILDCARD_MATCH', 'SPECIFIC_RESOURCE',
]);

export const RuleRequirementSchema = z.object({
    id: z.string().describe('Requirement identifier (e.g., REQ-01)'),
    description: z.string().describe('Format-agnostic scenario description — no IaC property names, resource types, or intrinsic functions'),
    category: RequirementCategorySchema.describe('Scenario category from the mandatory list'),
    expectedBehavior: z.enum(['flag', 'pass']).describe('Whether the rule should fire (flag) or not (pass)'),
    rationale: z.string().describe('Why this expected behavior is correct, referencing AWS docs or rule semantics')
});

const AmbiguityOptionSchema = z.object({
    label: z.string().describe('Short description of this interpretation'),
    expectedBehavior: z.enum(['flag', 'pass']).describe('What the rule should do under this interpretation'),
});

export const AmbiguitySchema = z.object({
    scenario: z.string().describe('The ambiguous scenario'),
    question: z.string().describe('Question to present to a human for resolution'),
    options: z.array(AmbiguityOptionSchema).min(2).describe('Possible interpretations'),
});

export const RequirementsOutputSchema = z.object({
    requirements: z.array(RuleRequirementSchema).min(1).describe('Complete requirements specification'),
    cfnResources: z.array(z.string()).describe('List of CloudFormation resource types that trigger the rule'),
    tfResources: z.array(z.string()).describe('List of Terraform resource types that trigger the rule'),
    ambiguities: z.array(AmbiguitySchema).describe('Scenarios where the expected behavior is genuinely ambiguous and requires human decision'),
    awsDocReferences: z.array(z.string()).describe('AWS documentation URLs consulted'),
});
