import * as path from 'path';
import { FixChange } from '../../../types.js';
import { ProjectContext } from '../../../../shared/project/project-context.js';
import { CdkSynthesizer } from '../../../../shared/cdk/cdk-synthesizer.js';
import { CdkProjectConfig } from '../../../../shared/cdk/types.js';
import { StrategyResult, ValidationStrategy } from '../types.js';

/**
 * Runs `cdk synth` for each CDK project that contains at least one staged edit.
 * Surfaces the synthesizer's error message so the model can react to it.
 */
export class CdkSynthStrategy implements ValidationStrategy {
    public readonly name = 'cdk-synth';

    public async validate(changes: FixChange[], context: ProjectContext): Promise<StrategyResult[]> {
        const cdkProjects = await context.getAllCdkProjects();
        if (cdkProjects.length === 0) return [];

        const affectedProjects = this.findAffectedProjects(changes, cdkProjects);
        if (affectedProjects.length === 0) return [];

        const synthesizer = new CdkSynthesizer(context);
        const results: StrategyResult[] = [];

        for (const project of affectedProjects) {
            const result = await synthesizer.synthesizeProject(project);
            results.push({
                strategy: `${this.name}:${project.name}`,
                isValid: result.success,
                output: result.success ? undefined : result.error,
            });
        }

        return results;
    }

    private findAffectedProjects(changes: FixChange[], cdkProjects: CdkProjectConfig[]): CdkProjectConfig[] {
        const affected = new Map<string, CdkProjectConfig>();
        for (const change of changes) {
            const normalisedPath = path.resolve(change.filePath);
            for (const project of cdkProjects) {
                const projectRoot = path.resolve(project.rootPath);
                if (this.isWithin(normalisedPath, projectRoot)) {
                    affected.set(project.rootPath, project);
                }
            }
        }
        return Array.from(affected.values());
    }

    private isWithin(childPath: string, parentPath: string): boolean {
        const rel = path.relative(parentPath, childPath);
        return !rel.startsWith('..') && !path.isAbsolute(rel);
    }
}
