import * as fs from 'node:fs';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import { RequirementsWorkflow } from '../requirements/requirements-workflow.js';
import { ScaffoldingWorkflow } from '../scaffolding/scaffolding-workflow.js';
import { ImplementationWorkflow } from '../implementation/implementation-workflow.js';
import { FixtureWorkflow } from '../fixtures/fixture-workflow.js';
import { RemediationWorkflow } from '../remediation/remediation-workflow.js';
import { UnitTestRunner } from '../shared/unit-test-runner.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const BUILD_PHASE_COUNT = 5;

export interface BuildOptions { regenerate?: boolean; }

export class BuildWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) { }

    public async run(options: BuildOptions = {}): Promise<void> {
        this.clearArtifactsIfRegenerating(options);

        this.logger.phaseStart(1, BUILD_PHASE_COUNT, 'Requirements');
        const requirements = await this.runRequirements();
        this.logger.phaseComplete(`${requirements.requirements.length} requirements generated`);

        this.logger.phaseStart(2, BUILD_PHASE_COUNT, 'Scaffolding');
        this.runScaffolding(requirements);
        this.logger.phaseComplete('control file + adapters scaffolded');

        this.logger.phaseStart(3, BUILD_PHASE_COUNT, 'Implementation');
        await this.runImplementation(requirements);
        this.verifyUnitTests('implementation');
        this.logger.phaseComplete(`${this.context.ruleId} implemented`);

        this.logger.phaseStart(4, BUILD_PHASE_COUNT, 'Fixtures');
        await this.runFixtures();
        this.logger.phaseComplete('fixtures generated');

        this.logger.phaseStart(5, BUILD_PHASE_COUNT, 'Remediation');
        await this.runRemediation();
        this.verifyUnitTests('remediation');
        this.logger.phaseComplete('remediations tested');
    }

    private verifyUnitTests(phase: string): void {
        const result = new UnitTestRunner(this.context.srtRootFolderPath, this.context.testsFolderPath).run();
        if (result.passed) return;
        this.logger.info(result.output);
        throw new Error(`Unit tests for ${this.context.ruleId} fail after ${phase}.`);
    }

    private clearArtifactsIfRegenerating(options: BuildOptions): void {
        if (!options.regenerate) return;
        this.logger.info(`Regenerating ${this.context.ruleId}: clearing tests, control, and adapter files`);
        fs.rmSync(this.context.testsFolderPath, { recursive: true, force: true });
        fs.rmSync(this.context.ruleControlFilePath, { force: true });
        fs.rmSync(this.context.ruleAdapterBaseFilePath, { force: true });
        fs.rmSync(this.context.ruleAdapterCfnFilePath, { force: true });
        fs.rmSync(this.context.ruleAdapterTfFilePath, { force: true });
    }

    private async runRequirements(): Promise<RequirementsSpec> {
        return new RequirementsWorkflow(this.context).run({ regenerate: false });
    }

    private runScaffolding(requirements: RequirementsSpec): void {
        new ScaffoldingWorkflow(this.context).run(requirements);
    }

    private async runImplementation(requirements: RequirementsSpec): Promise<void> {
        await new ImplementationWorkflow(this.context).run(requirements);
    }

    private async runFixtures(): Promise<void> {
        await new FixtureWorkflow(this.context).run();
    }

    private async runRemediation(): Promise<void> {
        await new RemediationWorkflow(this.context).run();
    }
}
