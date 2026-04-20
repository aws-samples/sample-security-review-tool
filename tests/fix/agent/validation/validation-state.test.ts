import { describe, it, expect } from 'vitest';
import { ValidationState } from '../../../../src/fix/agent/validation/validation-state.js';

describe('ValidationState', () => {
    it('reports the current edits as not validated until recordValidation with matching version', () => {
        const state = new ValidationState();
        state.bumpEditVersion();

        expect(state.isCurrentEditValidated()).toBe(false);

        state.recordValidation({ isValid: true, checks: [] });

        expect(state.isCurrentEditValidated()).toBe(true);
    });

    it('invalidates a prior passing validation when new edits bump the version', () => {
        const state = new ValidationState();
        state.bumpEditVersion();
        state.recordValidation({ isValid: true, checks: [] });

        state.bumpEditVersion();

        expect(state.isCurrentEditValidated()).toBe(false);
    });

    it('does not mark a failing validation as validated', () => {
        const state = new ValidationState();
        state.bumpEditVersion();

        state.recordValidation({
            isValid: false,
            checks: [{ strategy: 'cdk-synth', isValid: false, output: 'boom' }],
        });

        expect(state.isCurrentEditValidated()).toBe(false);
        expect(state.getLastResult()?.isValid).toBe(false);
    });
});
