import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';

const CONTROLS_IMPORT_PLACEHOLDER = '../../../../src/assess/scanning/security-matrix/controls/';
const CONTROLS_IMPORT_OUTPUT = '../../../controls/';

export class Substitutions {
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
