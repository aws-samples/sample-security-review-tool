import { Template } from 'cloudform-types';
import { parseCfnTemplate } from '../../../../../src/assess/scanning/security-matrix/cfn-utils.js';
import type { BaseRule, Resource } from '../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import type { BaseTerraformRule, TerraformResource } from '../../../../../src/assess/scanning/security-matrix/terraform-rule-base.js';
import type { RuleRequirement } from '../../shared/types/requirements.js';
import type { GeneratedFixture } from '../../shared/types/fixtures.js';
import type { ValidationDiagnostics, ValidationResult } from '../../shared/types/validation.js';
import { buildCloudFormationTemplate, buildTerraformResources } from './template-builder.js';
import { loadCloudFormationRule, loadTerraformRule } from './rule-loader.js';
import { RuleCatalog } from '../../shared/rule-catalog/index.js';

export async function validateRequirement(checkId: string, format: 'cfn' | 'terraform', requirement: RuleRequirement, fixture: GeneratedFixture): Promise<ValidationResult> {
    await RuleCatalog.refresh();

    if (format === 'terraform') {
        const rule = await loadTerraformRule(checkId);
        return validateTerraformRequirement(rule, checkId, requirement, fixture);
    }

    const rule = await loadCloudFormationRule(checkId);
    return validateCloudFormationRequirement(rule, checkId, requirement, fixture);
}

function validateCloudFormationRequirement(rule: BaseRule, checkId: string, requirement: RuleRequirement, fixture: GeneratedFixture): ValidationResult {
    const diagnostics: ValidationDiagnostics = {
        ruleWasInvoked: false,
        matchedResourceTypes: [],
        templateResourceTypes: [],
        fixtureStructureValid: false,
        suggestedCause: 'unknown',
    };

    let template: Template;
    try {
        const rawTemplate = buildCloudFormationTemplate(fixture.templateSnippet);
        template = parseCfnTemplate(rawTemplate);
        diagnostics.fixtureStructureValid = true;
        diagnostics.resolvedTemplate = JSON.stringify(template.Resources, null, 2);
    } catch (error) {
        diagnostics.parseError = (error as Error).message;
        diagnostics.suggestedCause = 'fixture_parse_error';
        return { requirementId: requirement.id, passed: false, expected: requirement.expectedBehavior, actual: 'error', diagnostics };
    }

    if (!template.Resources) {
        diagnostics.suggestedCause = 'fixture_wrong_structure';
        return { requirementId: requirement.id, passed: false, expected: requirement.expectedBehavior, actual: 'error', diagnostics };
    }

    for (const [_, resource] of Object.entries(template.Resources)) {
        diagnostics.templateResourceTypes.push(resource.Type);
        if (rule.appliesTo(resource.Type)) {
            diagnostics.ruleWasInvoked = true;
            diagnostics.matchedResourceTypes.push(resource.Type);
        }
    }

    if (!diagnostics.ruleWasInvoked) {
        diagnostics.suggestedCause = 'fixture_missing_resource';
        return { requirementId: requirement.id, passed: false, expected: requirement.expectedBehavior, actual: 'pass', diagnostics };
    }

    let fired = false;
    try {
        fired = evaluateAllResources(rule, template, checkId);
    } catch (error) {
        const errorMessage = (error as Error).message;
        diagnostics.evaluationError = errorMessage;
        diagnostics.suggestedCause = classifyEvaluationError(errorMessage);
        return { requirementId: requirement.id, passed: false, expected: requirement.expectedBehavior, actual: 'error', diagnostics };
    }

    const actual: 'flag' | 'pass' = fired ? 'flag' : 'pass';
    const passed = actual === requirement.expectedBehavior;

    if (!passed) {
        diagnostics.suggestedCause = 'rule_logic';
    }

    return { requirementId: requirement.id, passed, expected: requirement.expectedBehavior, actual, diagnostics };
}

function classifyEvaluationError(errorMessage: string): ValidationDiagnostics['suggestedCause'] {
    const lower = errorMessage.toLowerCase();
    if (lower.includes('cannot read properties of undefined') || lower.includes('is not a function')) return 'value_mismatch';
    if (lower.includes('not found in template')) return 'cross_resource_not_found';
    if (lower.includes('fn::if') || lower.includes('fn::importvalue')) return 'intrinsic_not_handled';
    return 'rule_logic';
}

function evaluateAllResources(rule: BaseRule, template: Template, checkId: string): boolean {
    for (const resourceId in template.Resources) {
        const resource: Resource = template.Resources[resourceId];

        if (!rule.appliesTo(resource.Type)) continue;

        const result = rule.evaluateResource('test-stack', template, resource);

        if (result === undefined) {
            const cfResource = {
                Type: resource.Type,
                Properties: resource.Properties || {},
                LogicalId: resourceId,
                Metadata: resource.Metadata,
            };
            const allCfResources = Object.entries(template.Resources).map(
                ([id, res]: [string, any]) => ({
                    Type: res.Type,
                    Properties: res.Properties || {},
                    LogicalId: id,
                }),
            );
            const legacyResult = rule.evaluate(cfResource, 'test-stack', allCfResources);
            if (legacyResult && legacyResult.check_id === checkId) return true;
        } else if (result && result.check_id === checkId) {
            return true;
        }
    }
    return false;
}

function validateTerraformRequirement(rule: BaseTerraformRule, checkId: string, requirement: RuleRequirement, fixture: GeneratedFixture): ValidationResult {
    const diagnostics: ValidationDiagnostics = {
        ruleWasInvoked: false,
        matchedResourceTypes: [],
        templateResourceTypes: [],
        fixtureStructureValid: false,
        suggestedCause: 'unknown',
    };

    let resources: TerraformResource[];
    try {
        resources = buildTerraformResources(fixture.templateSnippet);
        diagnostics.fixtureStructureValid = true;
    } catch (error) {
        diagnostics.parseError = (error as Error).message;
        diagnostics.suggestedCause = 'fixture_parse_error';
        return { requirementId: requirement.id, passed: false, expected: requirement.expectedBehavior, actual: 'error', diagnostics };
    }

    for (const resource of resources) {
        diagnostics.templateResourceTypes.push(resource.type);
        if (rule.appliesTo(resource.type)) {
            diagnostics.ruleWasInvoked = true;
            diagnostics.matchedResourceTypes.push(resource.type);
        }
    }

    if (!diagnostics.ruleWasInvoked) {
        diagnostics.suggestedCause = 'fixture_missing_resource';
        return { requirementId: requirement.id, passed: false, expected: requirement.expectedBehavior, actual: 'pass', diagnostics };
    }

    let fired = false;
    try {
        fired = evaluateAllTerraformResources(rule, resources, checkId);
    } catch (error) {
        diagnostics.evaluationError = (error as Error).message;
        diagnostics.suggestedCause = 'rule_logic';
        return { requirementId: requirement.id, passed: false, expected: requirement.expectedBehavior, actual: 'error', diagnostics };
    }

    const actual: 'flag' | 'pass' = fired ? 'flag' : 'pass';
    const passed = actual === requirement.expectedBehavior;

    if (!passed) {
        diagnostics.suggestedCause = 'rule_logic';
    }

    return { requirementId: requirement.id, passed, expected: requirement.expectedBehavior, actual, diagnostics };
}

function evaluateAllTerraformResources(rule: BaseTerraformRule, resources: TerraformResource[], checkId: string): boolean {
    for (const resource of resources) {
        if (!rule.appliesTo(resource.type)) continue;

        const result = rule.evaluate(resource, 'test-project', resources);
        if (result && result.check_id === checkId) return true;
    }
    return false;
}
