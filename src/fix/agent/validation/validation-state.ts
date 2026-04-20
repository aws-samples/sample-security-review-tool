import { ValidationResult } from './types.js';

/**
 * Shared state between the EditRecorder, ValidateFixTool, and FinishTool.
 *
 * Every staged edit bumps `editVersion`; ValidateFixTool records the version
 * at which the last validation passed. FinishTool consults this state to
 * decide whether the agent is allowed to end the session.
 */
export class ValidationState {
    private editVersion = 0;
    private lastPassedVersion: number | null = null;
    private lastResult: ValidationResult | null = null;

    public bumpEditVersion(): void {
        this.editVersion += 1;
    }

    public recordValidation(result: ValidationResult): void {
        this.lastResult = result;
        if (result.isValid) {
            this.lastPassedVersion = this.editVersion;
        }
    }

    public getCurrentEditVersion(): number {
        return this.editVersion;
    }

    public isCurrentEditValidated(): boolean {
        return this.lastPassedVersion !== null && this.lastPassedVersion === this.editVersion;
    }

    public getLastResult(): ValidationResult | null {
        return this.lastResult;
    }
}
