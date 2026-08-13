import * as path from 'path';
import * as fs from 'fs/promises';
import { FixChange } from '../../../types.js';
import { ProjectContext } from '../../../../shared/project/project-context.js';
import { TerraformProjectConfig } from '../../../../shared/terraform/types.js';
import { CommandRunner } from '../../../../shared/command-execution/command-runner.js';
import { StrategyResult, ValidationStrategy } from '../types.js';

export class TerraformValidateStrategy implements ValidationStrategy {
    public readonly name = 'terraform-validate';

    private readonly commandRunner = new CommandRunner();

    public async validate(changes: FixChange[], context: ProjectContext): Promise<StrategyResult[]> {
        const tfChanges = changes.filter(c => c.filePath.endsWith('.tf'));
        if (tfChanges.length === 0) return [];

        const projects = await context.getTerraformPlans();
        if (projects.length === 0) return [];

        const results: StrategyResult[] = [];

        for (const change of tfChanges) {
            const result = await this.fmtCheck(change.filePath);
            results.push(result);
        }

        const affectedProjects = this.findAffectedProjects(tfChanges, projects);
        for (const project of affectedProjects) {
            if (await this.hasInstalledProviders(project.rootPath)) {
                const result = await this.terraformValidate(project);
                results.push(result);
            }
        }

        return results;
    }

    private async fmtCheck(filePath: string): Promise<StrategyResult> {
        const strategy = `${this.name}:fmt:${path.basename(filePath)}`;
        try {
            await this.commandRunner.exec(
                `terraform fmt -check -diff "${filePath}"`,
                path.dirname(filePath),
                true,
            );
            return { strategy, isValid: true };
        } catch (error) {
            return { strategy, isValid: false, output: this.extractOutput(error) };
        }
    }

    private async terraformValidate(project: TerraformProjectConfig): Promise<StrategyResult> {
        const strategy = `${this.name}:validate:${project.name}`;
        try {
            await this.commandRunner.exec(
                'terraform validate -json',
                project.rootPath,
                true,
            );
            return { strategy, isValid: true };
        } catch (error) {
            return { strategy, isValid: false, output: this.extractOutput(error) };
        }
    }

    private findAffectedProjects(changes: FixChange[], projects: TerraformProjectConfig[]): TerraformProjectConfig[] {
        const affected = new Map<string, TerraformProjectConfig>();
        for (const change of changes) {
            const normalised = path.resolve(change.filePath);
            for (const project of projects) {
                const projectRoot = path.resolve(project.rootPath);
                if (this.isWithin(normalised, projectRoot)) {
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

    private async hasInstalledProviders(rootPath: string): Promise<boolean> {
        try {
            await fs.access(path.join(rootPath, '.terraform', 'providers'));
            return true;
        } catch {
            return false;
        }
    }

    private extractOutput(error: unknown): string {
        const anyError = error as { stderr?: string; stdout?: string; message?: string };
        const stderr = (anyError.stderr ?? '').toString().trim();
        const stdout = (anyError.stdout ?? '').toString().trim();
        const message = anyError.message ?? 'Command failed';
        return [stderr, stdout, message].filter(part => part.length > 0).join('\n');
    }
}
