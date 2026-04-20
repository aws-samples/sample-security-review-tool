import { describe, it, expect } from 'vitest';
import { FinishTool } from '../../../../src/fix/agent/tools/finish-tool.js';
import { EditRecorder } from '../../../../src/fix/agent/edit-recorder.js';
import { ValidationState } from '../../../../src/fix/agent/validation/validation-state.js';

function buildFinishTool(): { tool: FinishTool; recorder: EditRecorder; state: ValidationState } {
    const state = new ValidationState();
    const recorder = new EditRecorder(state);
    const tool = new FinishTool(recorder, state);
    return { tool, recorder, state };
}

describe('FinishTool', () => {
    it('accepts finish when no edits have been staged', async () => {
        const { tool } = buildFinishTool();

        const result = await tool.invoke({ comments: 'Nothing to do.' });

        expect(result.isError).toBeFalsy();
        expect(tool.wasCalled()).toBe(true);
    });

    it('rejects finish when edits are staged but validation has not passed', async () => {
        const { tool, recorder } = buildFinishTool();
        recorder.recordOriginal('/tmp/a.ts', '');
        recorder.recordUpdate('/tmp/a.ts', 'updated');

        const result = await tool.invoke({ comments: 'Done.' });

        expect(result.isError).toBe(true);
        expect(tool.wasCalled()).toBe(false);
    });

    it('accepts finish once validation passes for the current edit version', async () => {
        const { tool, recorder, state } = buildFinishTool();
        recorder.recordOriginal('/tmp/a.ts', '');
        recorder.recordUpdate('/tmp/a.ts', 'updated');
        state.recordValidation({ isValid: true, checks: [] });

        const result = await tool.invoke({ comments: 'Done.' });

        expect(result.isError).toBeFalsy();
        expect(tool.wasCalled()).toBe(true);
    });

    it('re-rejects finish if a new edit is staged after a passing validation', async () => {
        const { tool, recorder, state } = buildFinishTool();
        recorder.recordOriginal('/tmp/a.ts', '');
        recorder.recordUpdate('/tmp/a.ts', 'v1');
        state.recordValidation({ isValid: true, checks: [] });
        recorder.recordUpdate('/tmp/a.ts', 'v2');

        const result = await tool.invoke({ comments: 'Done.' });

        expect(result.isError).toBe(true);
        expect(tool.wasCalled()).toBe(false);
    });
});
