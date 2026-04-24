import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import type { RefinerSession, RefinerResult } from '../types.js';

const ratingEnum = z.enum(['HIGH', 'MEDIUM', 'LOW']);
const correctnessEnum = z.enum(['CORRECT', 'PARTIAL', 'INCORRECT']);

export function createSubmitResultTool(session: RefinerSession) {
    return tool({
        name: 'submit_result',
        description: 'Submit the final structured result for this rule refinement. Call exactly once when done.',
        inputSchema: z.object({
            checkId: z.string(),
            phase1: z.object({
                correctness: correctnessEnum,
                correctnessReasoning: z.string(),
                awsDocCitations: z.array(z.string()),
                missedCases: z.array(z.string()),
                falsePositiveRisks: z.array(z.string()),
                knownLimitations: z.array(z.string()),
                detectionLogicEdited: z.boolean(),
                editSummary: z.string(),
            }),
            phase2: z.object({
                variantResults: z.array(z.object({
                    variantId: z.string(),
                    format: z.string(),
                    effectiveness: ratingEnum,
                    effectivenessReasoning: z.string(),
                    efficiency: ratingEnum,
                    efficiencyReasoning: z.string(),
                    rescanPassed: z.boolean(),
                    fixGuidanceEdited: z.boolean(),
                    editSummary: z.string(),
                })),
            }),
        }),
        callback: async (input): Promise<JSONValue> => {
            if (session.result !== null) {
                return { accepted: false, reason: 'submit_result already called' };
            }
            session.result = input as RefinerResult;
            return { accepted: true };
        },
    });
}
