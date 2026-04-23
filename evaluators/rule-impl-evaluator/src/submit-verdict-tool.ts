import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import type { Correctness, ReviewerSession, RuleImplVerdict } from './types.js';

const verdictSchema = z.object({
    correctness: z.enum(['CORRECT', 'PARTIAL', 'INCORRECT'])
        .describe('CORRECT = detection logic matches AWS best-practice; PARTIAL = mainline case works but misses paths or has false-positive risk; INCORRECT = structurally wrong.'),
    correctnessReasoning: z.string().min(1)
        .describe('Why you rated the rule this way, grounded in specific AWS doc evidence.'),
    awsDocCitations: z.array(z.string().url())
        .describe('URLs of AWS doc pages you consulted to form this verdict. At least one required if correctness is anything other than CORRECT; strongly recommended always.'),
    missedCases: z.array(z.string())
        .describe('Config patterns that should trigger the finding but do not. Empty array if none.'),
    falsePositiveRisks: z.array(z.string())
        .describe('Config patterns that trigger the finding but are actually compliant. Empty array if none.'),
    suggestedLogicChanges: z.string()
        .describe('Concrete proposed changes to the rule code if correctness is not CORRECT. Empty string if CORRECT.'),
});

const SUBMIT_VERDICT_DESCRIPTION = [
    'Submit the final verdict on this rule\'s detection logic.',
    'Call this exactly once per review, after gathering evidence via the AWS Knowledge MCP tools.',
    'Every field must be populated per the schema.',
].join(' ');

export function createSubmitVerdictTool(
    session: ReviewerSession,
    checkId: string,
    ruleDescription: string,
    ruleSourceHash: string,
) {
    return tool({
        name: 'submit_impl_verdict',
        description: SUBMIT_VERDICT_DESCRIPTION,
        inputSchema: verdictSchema,
        callback: async (input): Promise<JSONValue> => {
            if (session.verdict !== null) {
                return {
                    accepted: false,
                    reason: 'submit_impl_verdict was already called for this review. Do not call it again.',
                };
            }
            const verdict: RuleImplVerdict = {
                checkId,
                ruleDescription,
                correctness: input.correctness as Correctness,
                correctnessReasoning: input.correctnessReasoning,
                awsDocCitations: input.awsDocCitations,
                missedCases: input.missedCases,
                falsePositiveRisks: input.falsePositiveRisks,
                suggestedLogicChanges: input.suggestedLogicChanges,
                ruleSourceHash,
            };
            session.verdict = verdict;
            return { accepted: true };
        },
    });
}
