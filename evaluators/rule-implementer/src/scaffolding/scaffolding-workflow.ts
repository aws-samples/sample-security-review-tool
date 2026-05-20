import * as fs from 'node:fs';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import { Substitutions } from './substitutions.js';
import { TemplateRenderer } from './template-renderer.js';
import { RegistrationWriter } from './registration-writer.js';

export class ScaffoldingWorkflow {
    constructor(private readonly context: RuleContext) { }

    public scaffold(spec: RequirementsSpec): void {
        if (fs.existsSync(this.context.ruleControlFilePath)) return;

        const substitutions = new Substitutions(this.context, spec);

        this.createRuleFolder();
        this.writeAdapterFiles(substitutions);
        this.writeControlFile(substitutions);
        new RegistrationWriter(this.context).register();
    }

    private createRuleFolder(): void {
        fs.mkdirSync(this.context.ruleFolderPath, { recursive: true });
    }

    private writeAdapterFiles(substitutions: Substitutions): void {
        new TemplateRenderer('__safe-rule-id__.adapter.ts').writeTo(this.context.ruleAdapterBaseFilePath, substitutions);
        new TemplateRenderer('__rule__.adapter.cfn.ts').writeTo(this.context.ruleAdapterCfnFilePath, substitutions);
        new TemplateRenderer('__rule__.adapter.tf.ts').writeTo(this.context.ruleAdapterTfFilePath, substitutions);
    }

    private writeControlFile(substitutions: Substitutions): void {
        new TemplateRenderer('__rule__.control.ts').writeTo(this.context.ruleControlFilePath, substitutions);
    }
}
