import { AgentTool, ToolOutput } from '../types.js';
import { EditRecorder } from '../edit-recorder.js';
import { ValidationState } from '../validation/validation-state.js';

/**
 * Terminal tool. The model calls this to signal that it has finished and to
 * provide a human-readable summary/comments string. The loop treats this as a
 * stop condition.
 *
 * Refuses to acknowledge the session as finished until validate_fix has
 * reported success for the current edit version. This prevents the model
 * from shipping a fix that has not passed cdk synth / tsc / py_compile.
 */
export class FinishTool implements AgentTool {
    private comments = '';
    private called = false;

    constructor(
        private readonly editRecorder: EditRecorder,
        private readonly validationState: ValidationState,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'finish',
            description:
                'Call this exactly once, after validate_fix has returned isValid=true for the current edits, with a short explanation of the change. This ends the session. ' +
                'It is an error to call finish before a successful validate_fix.',
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
        if (this.editRecorder.hasEdits() && !this.validationState.isCurrentEditValidated()) {
            return {
                text:
                    'Cannot finish: validate_fix has not passed for the current staged edits. ' +
                    'Call validate_fix first, address any reported failures, and only then call finish.',
                isError: true,
            };
        }

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
