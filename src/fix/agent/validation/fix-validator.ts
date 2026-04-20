import { FixChange } from '../../types.js';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { EditRecorder } from '../edit-recorder.js';
import { CdkSynthStrategy } from './strategies/cdk-synth-strategy.js';
import { CfnTemplateStrategy } from './strategies/cfn-template-strategy.js';
import { LanguageCheckStrategy } from './strategies/language-check-strategy.js';
import { StrategyResult, ValidationResult, ValidationStrategy } from './types.js';

/**
 * Orchestrates fix validation:
 *   1. Writes the staged edits from EditRecorder to disk.
 *   2. Runs each registered strategy (CDK synth, CFN template, language).
 *   3. Restores the original on-disk bytes so the CLI stays authoritative
 *      for the apply step.
 */
export class FixValidator {
    private readonly strategies: ValidationStrategy[];

    constructor(
        private readonly context: ProjectContext,
        private readonly editRecorder: EditRecorder,
        strategies?: ValidationStrategy[],
    ) {
        this.strategies = strategies ?? [
            new CdkSynthStrategy(),
            new CfnTemplateStrategy(),
            new LanguageCheckStrategy(),
        ];
    }

    public async validate(): Promise<ValidationResult> {
        const changes = this.editRecorder.toFixChanges();
        if (changes.length === 0) {
            return { isValid: true, checks: [] };
        }

        await this.editRecorder.applyToDisk();
        try {
            const checks = await this.runStrategies(changes);
            const failingCheck = checks.find(check => !check.isValid);
            return {
                isValid: !failingCheck,
                checks,
                failingCheck,
            };
        } finally {
            await this.editRecorder.revertToOriginal();
        }
    }

    private async runStrategies(changes: FixChange[]): Promise<StrategyResult[]> {
        const results: StrategyResult[] = [];
        for (const strategy of this.strategies) {
            const strategyResults = await strategy.validate(changes, this.context);
            results.push(...strategyResults);
        }
        return results;
    }
}
