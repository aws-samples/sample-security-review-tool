import z from 'zod';

export const IssueSchema = z.object({
    property: z.string().describe('The resource property, attribute, or code location involved'),
    description: z.string().describe('What is wrong'),
    documentation: z.string().describe('The AWS or Terraform provider doc reference that supports this finding'),
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

export const RuleAnnotationOutputSchema = z.object({
    jsdocComment: z.string().describe('The complete JSDoc comment block (including /** and */) to place above the class declaration'),
});

export const FixtureFileSchema = z.object({
    relativePath: z.string().describe('File path relative to the fixture root directory'),
    content: z.string().describe('Complete file content'),
});

export const FixtureSetSchema = z.object({
    variantId: z.string().describe('Variant identifier matching the createResult code path (e.g., "v1", "default")'),
    formatVariant: z.enum(['cfn', 'cdk', 'terraform']).describe('The IaC format of this fixture'),
    files: z.array(FixtureFileSchema).min(1).describe('All files comprising this fixture'),
    description: z.string().describe('What non-compliant condition this fixture exercises'),
});

export const RuleFixtureOutputSchema = z.object({
    fixtures: z.array(FixtureSetSchema).min(1).describe('One fixture set per variant per format variant'),
    rationale: z.string().describe('Why these fixtures collectively exercise all rule checks'),
});

export const FixInstructionUpdaterOutputSchema = z.object({
    updatedSource: z.string().describe('The complete updated rule source file with corrected fix guidance strings'),
    changesDescription: z.string().describe('Summary of which fix guidance strings were changed and why'),
});

export interface FixInstructionValidationResult {
    variantId: string;
    formatVariant: string;
    scanFoundIssue: boolean;
    scanError?: string;
    fixGenerated: boolean;
    fixResolved: boolean;
    fixError?: string;
    newIssuesIntroduced: string[];
    failureDetails?: string;
}