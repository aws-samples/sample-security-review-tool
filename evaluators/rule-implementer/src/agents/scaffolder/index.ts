import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';
import { RuleContext } from '../../shared/rule-context.js';
import type { RequirementsSpec } from '../../shared/types/requirements.js';
import { RegistrationWriter } from './registration-writer.js';

const TEMPLATE_DIR = path.dirname(url.fileURLToPath(import.meta.url));
const CONTROLS_IMPORT_PLACEHOLDER = '../../../../../src/assess/scanning/security-matrix/controls/';
const CONTROLS_IMPORT_OUTPUT = '../../../controls/';

export class RuleScaffolder {
    public scaffold(context: RuleContext, spec: RequirementsSpec): void {
        const substitutions = new Substitutions(context, spec);

        this.createRuleFolder(context);
        this.writeAdapterFiles(context, substitutions);
        this.writeControlFile(context, substitutions);
        new RegistrationWriter(context).register();
    }

    private createRuleFolder(context: RuleContext): void {
        fs.mkdirSync(context.ruleFolderPath, { recursive: true });
    }

    private writeAdapterFiles(context: RuleContext, substitutions: Substitutions): void {
        new TemplateRenderer('__safe-rule-id__.adapter.ts').writeTo(TEMPLATE_DIR, context.ruleAdapterBaseFilePath, substitutions);
        new TemplateRenderer('__rule__.adapter.cfn.ts').writeTo(TEMPLATE_DIR, context.ruleAdapterCfnFilePath, substitutions);
        new TemplateRenderer('__rule__.adapter.tf.ts').writeTo(TEMPLATE_DIR, context.ruleAdapterTfFilePath, substitutions);
    }

    private writeControlFile(context: RuleContext, substitutions: Substitutions): void {
        new TemplateRenderer('__rule__.control.ts').writeTo(TEMPLATE_DIR, context.ruleControlFilePath, substitutions);
    }
}

class TemplateRenderer {
    constructor(private readonly templateName: string) { }

    public writeTo(templateFolderPath: string, outputPath: string, substitutions: Substitutions): void {
        fs.writeFileSync(outputPath, this.render(templateFolderPath, substitutions));
    }

    private render(templateFolderPath: string, substitutions: Substitutions): string {
        const raw = fs.readFileSync(path.join(templateFolderPath, this.templateName), 'utf8');
        return substitutions.apply(raw);
    }
}

class Substitutions {
    public readonly ruleId: string;
    public readonly safeRuleId: string;
    public readonly service: string;
    public readonly description: string;
    private readonly cfnResourceTypes: string[];
    private readonly tfResourceTypes: string[];

    constructor(context: RuleContext, spec: RequirementsSpec) {
        this.ruleId = context.ruleId;
        this.safeRuleId = context.safeRuleId;
        this.service = context.service;
        this.description = context.description;
        this.cfnResourceTypes = spec.cfnResources;
        this.tfResourceTypes = spec.tfResources;
    }

    public apply(template: string): string {
        return template
            .replaceAll(CONTROLS_IMPORT_PLACEHOLDER, CONTROLS_IMPORT_OUTPUT)
            .replaceAll('__safe-rule-id__', this.safeRuleId)
            .replaceAll('__svc__', this.service)
            .replaceAll('__Rule__', this.ruleClassName())
            .replaceAll('__rule__', this.ruleInstanceName())
            .replaceAll('__RULE_ID__', this.ruleId)
            .replaceAll('__DESCRIPTION__', this.escapeForSingleQuoted(this.description))
            .replaceAll(`'__CFN_TYPES__'`, this.joinAsStringLiterals(this.cfnResourceTypes))
            .replaceAll(`'__TF_TYPES__'`, this.joinAsStringLiterals(this.tfResourceTypes));
    }

    private ruleClassName(): string {
        return this.ruleId.split('-').map(p => this.toPascalCase(p)).join('');
    }

    private ruleInstanceName(): string {
        const parts = this.ruleId.toLowerCase().split('-');
        return parts[0] + parts.slice(1).map(p => this.toPascalCase(p)).join('');
    }

    private toPascalCase(value: string): string {
        return value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
    }

    private escapeForSingleQuoted(value: string): string {
        return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    }

    private joinAsStringLiterals(values: string[]): string {
        return values.map(v => `'${this.escapeForSingleQuoted(v)}'`).join(', ');
    }
}
