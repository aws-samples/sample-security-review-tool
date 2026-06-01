import { RuleContext } from '../shared/rule-context.js';
import { UnitTestRunner } from '../shared/unit-test-runner.js';
import { RemediationWorkflow } from '../remediation/remediation-workflow.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const EXERCISE_PHASE_COUNT = 2;

export class ExerciseWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<void> {
        this.logger.phaseStart(1, EXERCISE_PHASE_COUNT, 'Unit Tests');
        this.runUnitTests();
        this.logger.phaseComplete('unit tests passed');

        this.logger.phaseStart(2, EXERCISE_PHASE_COUNT, 'Remediation');
        await this.runRemediation();
        this.logger.phaseComplete('remediations tested');
    }

    private runUnitTests(): void {
        const result = new UnitTestRunner(this.context.srtRootFolderPath, this.context.testsFolderPath).run();
        this.logger.info(result.output);
        if (!result.passed) throw new Error(`Unit tests failed for ${this.context.ruleId}`);
    }

    private async runRemediation(): Promise<void> {
        await new RemediationWorkflow(this.context).run();
    }
}
