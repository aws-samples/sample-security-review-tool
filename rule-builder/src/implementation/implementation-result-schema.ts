import z from 'zod';

export const ImplementationResultSchema = z.object({
    status: z.enum(['success', 'conflict']).describe('Whether implementation succeeded or hit an irreconcilable conflict'),
    currentRequirementId: z.string().optional().describe('The requirement being implemented (e.g. REQ-05). Required when status is conflict.'),
    conflictingRequirementId: z.string().optional().describe('The earlier requirement whose tests now break (e.g. REQ-03). Required when status is conflict.'),
    explanation: z.string().optional().describe('Why these two requirements are irreconcilable in this IaC format. Required when status is conflict.'),
});

export type ImplementationResult = z.infer<typeof ImplementationResultSchema>;
