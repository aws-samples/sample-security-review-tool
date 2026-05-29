import * as fs from 'node:fs';
import * as path from 'node:path';
import { select } from '@inquirer/prompts';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import type { ImplementationResult } from './implementation-result-schema.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

export interface ConflictResolution {
    removedRequirementId: string;
}

export class ImplementationConflictResolver {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) {}

    public async resolve(conflict: ImplementationResult, spec: RequirementsSpec): Promise<ConflictResolution> {
        const currentId = conflict.currentRequirementId!;
        const conflictingId = conflict.conflictingRequirementId!;

        this.printConflictSummary(currentId, conflictingId, conflict.explanation!, spec);
        const removedId = await this.promptUserForResolution(currentId, conflictingId, spec);
        this.deleteTestFiles(removedId);
        this.removeRequirementFromSpec(removedId, spec);
        this.persistSpec(spec);
        return { removedRequirementId: removedId };
    }

    private printConflictSummary(currentId: string, conflictingId: string, explanation: string, spec: RequirementsSpec): void {
        const current = spec.requirements.find(r => r.id === currentId);
        const conflicting = spec.requirements.find(r => r.id === conflictingId);

        this.logger.warning(`Conflict detected between ${currentId} and ${conflictingId}`);
        this.logger.step(explanation);
        if (current) this.logger.substep(`${current.id}: "${current.description}" → ${current.expectedBehavior}`);
        if (conflicting) this.logger.substep(`${conflicting.id}: "${conflicting.description}" → ${conflicting.expectedBehavior}`);
    }

    private async promptUserForResolution(currentId: string, conflictingId: string, spec: RequirementsSpec): Promise<string> {
        const currentReq = spec.requirements.find(r => r.id === currentId);
        const conflictingReq = spec.requirements.find(r => r.id === conflictingId);

        const choices = [
            { value: currentId, name: `Remove ${currentId}: ${currentReq?.description ?? 'unknown'}` },
            { value: conflictingId, name: `Remove ${conflictingId}: ${conflictingReq?.description ?? 'unknown'}` },
        ];

        return select({ message: 'Which requirement should be removed?', choices });
    }

    private deleteTestFiles(requirementId: string): void {
        const cfnPath = path.join(this.context.testsFolderPath, `${requirementId}.cfn.test.ts`);
        const tfPath = path.join(this.context.testsFolderPath, `${requirementId}.tf.test.ts`);

        if (fs.existsSync(cfnPath)) fs.unlinkSync(cfnPath);
        if (fs.existsSync(tfPath)) fs.unlinkSync(tfPath);

        this.logger.step(`Deleted test files for ${requirementId}`);
    }

    private removeRequirementFromSpec(requirementId: string, spec: RequirementsSpec): void {
        spec.requirements = spec.requirements.filter(r => r.id !== requirementId);
    }

    private persistSpec(spec: RequirementsSpec): void {
        fs.writeFileSync(this.context.requirementsFilePath, JSON.stringify(spec, null, 2));
    }
}
