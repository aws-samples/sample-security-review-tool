import z from 'zod';

export const RuleImplementationAssessmentOutputSchema = z.object({
    issues: z.array(z.object({
        property: z.string().describe('The CloudFormation property or code location involved'),
        description: z.string().describe('What is wrong'),
        documentation: z.string().describe('The AWS doc reference that supports this finding'),
        severity: z.enum(['high', 'low']).describe('High = incorrect behavior. Low = edge case or minor gap'),
    })).describe('Specific issues found in the detection logic'),
    limitations: z.array(z.string()).describe('Architectural limitations (cross-stack, etc.) that are not fixable'),
    summary: z.string().describe('One-paragraph overall assessment'),
});