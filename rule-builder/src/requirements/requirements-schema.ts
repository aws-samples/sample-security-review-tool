import z from 'zod';

export const DecisionPointSchema = z.object({
    id: z.string().describe('Decision point identifier (e.g., DP-1)'),
    description: z.string().describe('The value this rule\'s verdict turns on, stated format-agnostically'),
});

export const DraftRequirementSchema = z.object({
    id: z.string().describe('Requirement identifier (e.g., REQ-01)'),
    decisionPointId: z.string().describe('The id of the declared decision point this scenario exercises'),
    description: z.string().describe('The configuration, stated format-agnostically — no IaC property names, resource types, or intrinsic functions, and no claim about whether it passes or fails'),
});

export const RequirementsOutputSchema = z.object({
    decisionPoints: z.array(DecisionPointSchema).min(1).describe('The values this rule\'s verdict turns on, derived from the rule description'),
    requirements: z.array(DraftRequirementSchema).min(1).describe('One entry per configuration the rule must reach a verdict on'),
    cfnResources: z.array(z.string()).describe('List of CloudFormation resource types that trigger the rule'),
    tfResources: z.array(z.string()).describe('List of Terraform resource types that trigger the rule'),
});

export const ResolutionSchema = z.object({
    expectedBehavior: z.enum(['flag', 'pass']).describe('Whether the rule should fire (flag) or not (pass) for this configuration'),
    rationale: z.string().describe('The reason for the verdict in one sentence, readable on its own'),
    evidence: z.string().describe('The full account — what was searched, what it said, why it decides this'),
    docReference: z.string().nullable().describe('URL of the AWS documentation that settles it, or null when none was found'),
    settledBy: z.enum(['documentation', 'strict-default', 'intrinsic-exception']).describe('documentation when a cited doc decides it, strict-default when no doc settles it, intrinsic-exception when the value is unresolvable at analysis time'),
});

export const JointResolutionSchema = z.object({
    premise: z.string().describe('The single question both configurations turn on, and the answer the documentation gives it'),
    resolutions: z.array(ResolutionSchema.extend({
        requirementId: z.string().describe('The id of the requirement this verdict belongs to'),
    })).describe('One verdict per configuration, both following from the same answer to the premise'),
});
