import { Template } from 'cloudform-types';
import { parseCfnTemplate } from '../../../../../src/assess/scanning/security-matrix/cfn-utils.js';
import type { BaseRule, Resource } from '../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import type { BaseTerraformRule, TerraformResource } from '../../../../../src/assess/scanning/security-matrix/terraform-rule-base.js';
import type { RuleRequirement } from '../../types/requirements.js';
import type { GeneratedFixture } from '../fixture-generator/types.js';
import type { ValidationDiagnostics, ValidationResult, ValidationSummary } from './types.js';
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

export async function validateRequirements(checkId: string, format: 'cfn' | 'terraform', requirements: RuleRequirement[], fixtures: Map<string, GeneratedFixture>): Promise<ValidationSummary> {
    await RuleCatalog.refresh();

    const results: ValidationResult[] = [];

    for (const req of requirements) {
        const fixture = fixtures.get(req.id);
        if (!fixture) {
            results.push({
                requirementId: req.id,
                passed: false,
                expected: req.expectedBehavior,
                actual: 'error',
                diagnostics: { ruleWasInvoked: false, matchedResourceTypes: [], templateResourceTypes: [], fixtureStructureValid: false, suggestedCause: 'unknown' },
            });
            continue;
        }

        if (format === 'terraform') {
            const rule = await loadTerraformRule(checkId);
            results.push(validateTerraformRequirement(rule, checkId, req, fixture));
        } else {
            const rule = await loadCloudFormationRule(checkId);
            results.push(validateCloudFormationRequirement(rule, checkId, req, fixture));
        }
    }

    return {
        totalRequirements: requirements.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
        results,
    };
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
