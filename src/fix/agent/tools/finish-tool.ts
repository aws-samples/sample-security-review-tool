import { AgentTool, ToolOutput } from '../types.js';

/**
 * Terminal tool. The model calls this to signal that it has finished and to
 * provide a human-readable summary/comments string. The loop treats this as a
 * stop condition.
 */
export class FinishTool implements AgentTool {
    private comments = '';
    private called = false;

    public readonly definition = {
        toolSpec: {
            name: 'finish',
            description: 'Call this exactly once, after all apply_patch calls, with a short explanation of the change. This ends the session.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        comments: { type: 'string', description: 'Human-readable explanation of the fix.' },
                    },
                    required: ['comments'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        this.comments = String(input.comments ?? '');
        this.called = true;
        return { json: { acknowledged: true } };
    }

    public wasCalled(): boolean {
        return this.called;
    }

    public getComments(): string {
        return this.comments;
    }
}
