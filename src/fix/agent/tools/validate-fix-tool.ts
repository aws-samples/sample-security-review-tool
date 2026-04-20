import { AgentTool, ToolOutput } from '../types.js';
import { EditRecorder } from '../edit-recorder.js';
import { FixValidator } from '../validation/fix-validator.js';
import { ValidationState } from '../validation/validation-state.js';
import { ValidationResult } from '../validation/types.js';

const MAX_OUTPUT_CHARS = 4000;

/**
 * Tool the model invokes after staging edits and before calling finish.
 *
 * Applies the staged edits to disk, runs the appropriate validation
 * (cdk synth, cfn template parse, tsc / node --check / py_compile, etc.),
 * and reverts the disk changes. Validation failures are returned as an error
 * result so the model can inspect the output and adjust.
 */
export class ValidateFixTool implements AgentTool {
    constructor(
        private readonly editRecorder: EditRecorder,
        private readonly validator: FixValidator,
        private readonly validationState: ValidationState,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'validate_fix',
            description:
                'Validate the currently staged edits before calling finish. ' +
                'Applies the edits to disk, runs cdk synth (CDK projects), structural CloudFormation checks, or language checks (tsc, node --check, py_compile), then reverts the disk. ' +
                'Returns isValid=false with compiler/linter output if the fix is broken. ' +
                'You MUST call this after staging edits and only call finish once it returns isValid=true.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {},
                },
            },
        },
    };

    public async invoke(_input: Record<string, unknown>): Promise<ToolOutput> {
        if (!this.editRecorder.hasEdits()) {
            return {
                text: 'No staged edits to validate. Stage edits with edit_file or write_file first.',
                isError: true,
            };
        }

        try {
            const result = await this.validator.validate();
            this.validationState.recordValidation(result);
            return this.toToolOutput(result);
        } catch (error) {
            return {
                text: `validate_fix failed to run: ${(error as Error).message}`,
                isError: true,
            };
        }
    }

    private toToolOutput(result: ValidationResult): ToolOutput {
        const checks = result.checks.map(check => ({
            strategy: check.strategy,
            status: check.isValid ? 'passed' : 'failed',
        }));

        if (result.isValid) {
            return { json: { isValid: true, checks } };
        }

        const failing = result.failingCheck;
        return {
            json: {
                isValid: false,
                checks,
                failingCheck: failing?.strategy ?? 'unknown',
                output: this.truncate(failing?.output ?? ''),
                hint: 'Adjust the staged edits and call validate_fix again. Do not call finish until validate_fix reports isValid=true.',
            },
            isError: true,
        };
    }

    private truncate(output: string): string {
        if (output.length <= MAX_OUTPUT_CHARS) return output;
        return `${output.slice(0, MAX_OUTPUT_CHARS)}\n…[truncated ${output.length - MAX_OUTPUT_CHARS} chars]`;
    }
}
