import * as fs from 'node:fs';
import * as path from 'node:path';
import { select, input } from '@inquirer/prompts';
import z from 'zod';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import { RequirementsAgent } from './requirements-agent.js';
import { AmbiguitySchema } from './requirements-schema.js';

const CUSTOM_INTERPRETATION = -1;

export interface RequirementsWorkflowOptions {
    regenerate?: boolean;
}

export class RequirementsWorkflow {
    constructor(private readonly context: RuleContext) { }

    public async generate(options: RequirementsWorkflowOptions = {}): Promise<RequirementsSpec> {
        if (!options.regenerate && fs.existsSync(this.context.requirementsFilePath)) {
            return JSON.parse(fs.readFileSync(this.context.requirementsFilePath, 'utf8'));
        }

        const agent = new RequirementsAgent();
        let output = await agent.invoke(this.context.description);

        if (output.ambiguities.length > 0) {
            const resolvedDecisions = await this.resolveAmbiguities(output.ambiguities);
            output = await agent.invokeWithResolutions(this.context.description, resolvedDecisions);
        }

        const spec: RequirementsSpec = {
            ruleId: this.context.ruleId,
            generatedAt: new Date().toISOString(),
            description: this.context.description,
            cfnResources: output.cfnResources,
            tfResources: output.tfResources,
            requirements: output.requirements,
            awsDocReferences: output.awsDocReferences,
        };

        this.persist(spec);
        return spec;
    }

    private async resolveAmbiguities(ambiguities: z.infer<typeof AmbiguitySchema>[]): Promise<string[]> {
        const decisions: string[] = [];

        for (const ambiguity of ambiguities) {
            console.log(`\n  Ambiguity: ${ambiguity.scenario}`);

            const choices = [
                ...ambiguity.options.map((opt, i) => ({ value: i, name: `${opt.label} (→ ${opt.expectedBehavior})` })),
                { value: CUSTOM_INTERPRETATION, name: 'None of these — provide your own interpretation' },
            ];

            const answer = await select({ message: ambiguity.question, choices });

            if (answer === CUSTOM_INTERPRETATION) {
                decisions.push(await this.collectCustomInterpretation(ambiguity.scenario));
            } else {
                const chosen = ambiguity.options[answer];
                decisions.push(`- ${ambiguity.scenario}: should ${chosen.expectedBehavior}. Rationale: user chose "${chosen.label}".`);
            }
        }

        return decisions;
    }

    private async collectCustomInterpretation(scenario: string): Promise<string> {
        const description = await input({ message: 'Describe the correct interpretation:', validate: (v) => v.trim().length > 0 || 'Cannot be empty' });

        const behavior = await select<string | null>({ message: 'What should the expected behavior be?', choices: [
            { value: 'flag', name: 'Flag (rule should produce a finding)' },
            { value: 'pass', name: 'Pass (rule should return null)' },
            { value: null, name: 'Let Claude decide based on my description' },
        ]});

        if (behavior) {
            return `- ${scenario}: should ${behavior}. Rationale: user provided custom interpretation: "${description.trim()}".`;
        }
        return `- ${scenario}: user's interpretation: "${description.trim()}". Determine the correct expected behavior based on this description.`;
    }

    private persist(spec: RequirementsSpec): void {
        fs.mkdirSync(path.dirname(this.context.requirementsFilePath), { recursive: true });
        fs.writeFileSync(this.context.requirementsFilePath, JSON.stringify(spec, null, 2));
    }
}
