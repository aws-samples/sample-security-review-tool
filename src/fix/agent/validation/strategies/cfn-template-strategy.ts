import * as fs from 'fs/promises';
import * as path from 'path';
import * as yamlcfn from '@aws-cdk/yaml-cfn';
import { FixChange } from '../../../types.js';
import { ProjectContext } from '../../../../shared/project/project-context.js';
import { StrategyResult, ValidationStrategy } from '../types.js';

const TEMPLATE_EXTENSIONS = ['.yaml', '.yml', '.json'];

/**
 * Parses staged non-CDK CloudFormation templates to ensure they are still
 * well-formed and shaped like a CloudFormation document (Resources block with
 * typed entries). Intentionally static so no AWS credentials are required.
 */
export class CfnTemplateStrategy implements ValidationStrategy {
    public readonly name = 'cfn-template';

    public async validate(changes: FixChange[], context: ProjectContext): Promise<StrategyResult[]> {
        const templateChanges = await this.filterTemplates(changes, context);
        if (templateChanges.length === 0) return [];

        const results: StrategyResult[] = [];
        for (const change of templateChanges) {
            results.push(await this.validateTemplate(change.filePath));
        }
        return results;
    }

    private async filterTemplates(changes: FixChange[], context: ProjectContext): Promise<FixChange[]> {
        const candidates: FixChange[] = [];
        for (const change of changes) {
            const ext = path.extname(change.filePath).toLowerCase();
            if (!TEMPLATE_EXTENSIONS.includes(ext)) continue;
            if (await context.isCloudFormationTemplate(change.filePath)) {
                candidates.push(change);
            }
        }
        return candidates;
    }

    private async validateTemplate(filePath: string): Promise<StrategyResult> {
        const strategy = `${this.name}:${path.basename(filePath)}`;
        try {
            const content = await fs.readFile(filePath, 'utf-8');
            const parsed = this.parse(filePath, content);

            if (!parsed || typeof parsed !== 'object') {
                return { strategy, isValid: false, output: 'Template did not parse to an object.' };
            }

            const errors = this.collectStructuralErrors(parsed);
            if (errors.length > 0) {
                return { strategy, isValid: false, output: errors.join('\n') };
            }

            return { strategy, isValid: true };
        } catch (error) {
            return { strategy, isValid: false, output: (error as Error).message };
        }
    }

    private parse(filePath: string, content: string): Record<string, unknown> {
        const ext = path.extname(filePath).toLowerCase();
        if (ext === '.json') return JSON.parse(content);
        return yamlcfn.deserialize(content) as Record<string, unknown>;
    }

    private collectStructuralErrors(parsed: Record<string, unknown>): string[] {
        const errors: string[] = [];
        const resources = parsed.Resources as Record<string, unknown> | undefined;

        if (!resources || typeof resources !== 'object') {
            errors.push('Template is missing a "Resources" block.');
            return errors;
        }

        for (const [name, resource] of Object.entries(resources)) {
            if (!resource || typeof resource !== 'object') {
                errors.push(`Resource "${name}" is not an object.`);
                continue;
            }
            const type = (resource as Record<string, unknown>).Type;
            if (typeof type !== 'string' || type.length === 0) {
                errors.push(`Resource "${name}" is missing a "Type".`);
            }
        }

        return errors;
    }
}
