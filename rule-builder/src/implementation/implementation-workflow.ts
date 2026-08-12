import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { ImplementationConflictResolver } from './implementation-conflict-resolver.js';
import { TestCreationAgent } from './test-creation-agent.js';
import { assessTestFile } from './test-discrimination.js';
import { RuleImplementationAgent } from './rule-implementation-agent.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const MAX_CONFLICT_ESCALATIONS = 3;
const MAX_TEST_CREATION_ATTEMPTS = 3;

export class ImplementationWorkflow {
    private readonly testCreationAgent: TestCreationAgent;
    private readonly ruleImplementationAgent: RuleImplementationAgent;
    private readonly conflictResolver: ImplementationConflictResolver;
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) {
        this.testCreationAgent = new TestCreationAgent(context);
        this.ruleImplementationAgent = new RuleImplementationAgent(context);
        this.conflictResolver = new ImplementationConflictResolver(context);
    }

    public async run(spec: RequirementsSpec): Promise<void> {
        const attempted = new Set<string>();

        let requirement = this.nextUnimplemented(spec, attempted);
        while (requirement) {
            attempted.add(requirement.id);
            await this.createTestsThatProveTheRequirement(spec, requirement);
            await this.implementWithConflictResolution(spec, requirement);
            requirement = this.nextUnimplemented(spec, attempted);
        }
    }

    // Runs before the implementation, because an implementation written against tests that accept any
    // outcome is not verified by them passing. Failing the build is the point: the rule this guards
    // against shipped permissive with every one of its tests green.
    private async createTestsThatProveTheRequirement(spec: RequirementsSpec, requirement: RuleRequirement): Promise<void> {
        let problems: string[] = [];

        for (let attempt = 1; attempt <= MAX_TEST_CREATION_ATTEMPTS; attempt++) {
            await this.testCreationAgent.create(spec, requirement, problems);

            problems = await this.testFilesProvingNothing(requirement);
            if (problems.length === 0) return;

            this.logger.warning(`${requirement.id} tests do not prove the requirement (attempt ${attempt} of ${MAX_TEST_CREATION_ATTEMPTS})`);
            for (const problem of problems) this.logger.substep(problem);
        }

        throw new Error(`${requirement.id} tests still do not prove the requirement after ${MAX_TEST_CREATION_ATTEMPTS} attempts. ${problems.join('; ')}`);
    }

    private async testFilesProvingNothing(requirement: RuleRequirement): Promise<string[]> {
        const assessed = await Promise.all(this.testFileNames(requirement).map(async name => ({
            name,
            result: await assessTestFile(path.join(this.context.testsFolderPath, name), this.context.ruleControlFilePath, this.context.srtRootFolderPath),
        })));

        return assessed
            .filter(({ result }) => result.outcome === 'proves-nothing' || result.outcome === 'broken')
            .map(({ name, result }) => `${name}: ${result.reason}`);
    }

    private nextUnimplemented(spec: RequirementsSpec, attempted: Set<string>): RuleRequirement | undefined {
        return spec.requirements.find(requirement => !attempted.has(requirement.id) && !this.isAlreadyImplemented(requirement));
    }

    private isAlreadyImplemented(requirement: RuleRequirement): boolean {
        return this.testFileNames(requirement).every(name => fs.existsSync(path.join(this.context.testsFolderPath, name)));
    }

    private testFileNames(requirement: RuleRequirement): string[] {
        return [`${requirement.id}.cfn.test.ts`, `${requirement.id}.tf.test.ts`];
    }

    private async implementWithConflictResolution(spec: RequirementsSpec, requirement: RuleRequirement): Promise<boolean> {
        for (let attempt = 0; attempt < MAX_CONFLICT_ESCALATIONS; attempt++) {
            const result = await this.ruleImplementationAgent.implement(spec, requirement);
            if (result.status === 'success') return false;

            const resolution = await this.conflictResolver.resolve(result, spec);
            if (resolution.removedRequirementId === requirement.id) return true;
        }

        this.logger.warning(`Max conflict escalations reached for ${requirement.id}. Skipping.`);
        return false;
    }
}
