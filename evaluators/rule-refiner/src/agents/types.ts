import z from 'zod';

export const IssueSchema = z.object({
    property: z.string().describe('The CloudFormation property or code location involved'),
    description: z.string().describe('What is wrong'),
    documentation: z.string().describe('The AWS doc reference that supports this finding'),
    severity: z.enum(['high', 'low']).describe('High = incorrect behavior. Low = edge case or minor gap'),
});

export const RuleImplementationAssessmentOutputSchema = z.object({
    issues: z.array(IssueSchema).describe('Specific issues found in the detection logic'),
    limitations: z.array(z.string()).describe('Architectural limitations (cross-stack, etc.) that are not fixable'),
    summary: z.string().describe('One-paragraph overall assessment'),
});

export const RuleImplementationFixOutputSchema = z.object({
    updatedSource: z.string().describe('The complete updated rule source file'),
    explanation: z.string().describe('Brief description of what was changed and why'),
});