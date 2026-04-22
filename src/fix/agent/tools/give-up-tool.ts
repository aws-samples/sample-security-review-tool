import { tool } from '@strands-agents/sdk';
import z from 'zod';
import { AgentSession } from '../types.js';

const giveUpSchema = z.object({
    reason: z.string().min(1).describe('One or two sentences explaining why a valid fix could not be produced.'),
});

export function createGiveUpTool(session: AgentSession) {
    return tool({
        name: 'give_up',
        description: 'Abandon the fix attempt when you cannot produce a validated fix. Use only after reasonable attempts have failed.',
        inputSchema: giveUpSchema,
        callback: async (input) => {
            session.gaveUp = { reason: input.reason };
            session.editSession.reset();
            return { acknowledged: true };
        },
    });
}
