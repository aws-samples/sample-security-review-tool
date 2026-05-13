import * as fs from 'fs';
import * as path from 'path';
import { yamlParse } from 'yaml-cfn';
import { RuleCatalog } from '../shared/rule-catalog/index.js';
import { srtRepoRoot } from '../shared/fixture-paths.js';
import { validateRequirement } from '../agents/requirements-implementer/requirement-validator.js';
import { RequirementImplementationAgent } from '../agents/requirements-implementer/agent.js';
import { FixtureGeneratorAgent } from '../agents/fixture-generator/agent.js';
import { buildCloudFormationTemplate } from '../agents/requirements-implementer/template-builder.js';
import { parseCfnTemplate } from '../../../../src/assess/scanning/security-matrix/cfn-utils.js';
import type { RuleEntry } from '../shared/types/rule-catalog.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import type { GeneratedFixture, FixtureRegenerationContext, FixtureSet } from '../shared/types/fixtures.js';
import type { ValidationResult } from '../shared/types/validation.js';

const MAX_RETRIES = 2;

export interface ImplementationResult {
    totalRequirements: number;
    passed: number;
    failed: string[];
    testFilePath: string;
}

export async function implementRule(spec: RequirementsSpec, fixtureSets: FixtureSet[]): Promise<ImplementationResult> {
    const { ruleId, format, requirements } = spec;
    const agent = new RequirementImplementationAgent();
    const fixtureGenerator = new FixtureGeneratorAgent();
    const fixtures = new Map<string, GeneratedFixture>(fixtureSets.map(fs => [fs.requirement.id, fs.fixture]));

    console.log(`  Implementing ${requirements.length} requirements for ${ruleId}...`);

    for (let i = 0; i < requirements.length; i++) {
        const requirement = requirements[i];
        const allSoFar = requirements.slice(0, i + 1);
        const outcome = await processRequirement(ruleId, format, requirement, allSoFar, fixtures, agent, fixtureGenerator);
        console.log(`    ${outcome === 'unresolvable' ? '✗' : '✓'} ${requirement.id} ${outcome}`);
    }

    const passCount = await countPassing(ruleId, format, requirements, fixtures);
    const failedIds = await getFailedIds(ruleId, format, requirements, fixtures);

    console.log(`  Final state: ${passCount}/${requirements.length} requirements passing`);

    const rule = await RuleCatalog.find(ruleId, format);
    const testFilePath = writeTestFile(rule, ruleId, spec.requirements, fixtures);
    console.log(`  Written: ${testFilePath}`);

    return { totalRequirements: requirements.length, passed: passCount, failed: failedIds, testFilePath };
}

async function processRequirement(ruleId: string, format: 'cfn' | 'terraform', requirement: RuleRequirement, allSoFar: RuleRequirement[], fixtures: Map<string, GeneratedFixture>, agent: RequirementImplementationAgent, fixtureGenerator: FixtureGeneratorAgent): Promise<string> {
    const fixture = fixtures.get(requirement.id)!;

    let result = await validateRequirement(ruleId, format, requirement, fixture);
    if (result.passed) return 'already_passing';

    if (isFixtureProblem(result)) {
        return await escalate(ruleId, format, requirement, allSoFar, result, fixtures, agent, fixtureGenerator);
    }

    const resolvedTemplate = resolveFixtureForPrompt(fixture, format);

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const regressions = attempt === 0 ? [] : await findRegressions(ruleId, format, allSoFar, fixtures);
        await agent.invoke(ruleId, format, requirement, fixture, allSoFar, regressions, fixtures, resolvedTemplate);
        await RuleCatalog.refresh();

        result = await validateRequirement(ruleId, format, requirement, fixture);
        if (result.passed && (await findRegressions(ruleId, format, allSoFar, fixtures)).length === 0) {
            return 'implemented';
        }

        console.log(`      Attempt ${attempt + 1}: ${result.passed ? 'passed but regressions' : `failed (${result.diagnostics.suggestedCause})`}`);
    }

    return await escalate(ruleId, format, requirement, allSoFar, result, fixtures, agent, fixtureGenerator);
}

async function escalate(ruleId: string, format: 'cfn' | 'terraform', requirement: RuleRequirement, allSoFar: RuleRequirement[], lastResult: ValidationResult, fixtures: Map<string, GeneratedFixture>, agent: RequirementImplementationAgent, fixtureGenerator: FixtureGeneratorAgent): Promise<string> {
    console.log(`      Escalating: regenerating fixture for ${requirement.id}`);

    const rule = await RuleCatalog.find(ruleId, format);
    const regenerationContext: FixtureRegenerationContext = {
        previousFixture: fixtures.get(requirement.id)!.templateSnippet,
        failureDiagnostics: lastResult.diagnostics,
    };

    const newFixture = await fixtureGenerator.invoke(requirement, rule, format, regenerationContext);
    fixtures.set(requirement.id, newFixture);

    let result = await validateRequirement(ruleId, format, requirement, newFixture);
    if (result.passed) return 'fixture_was_wrong';

    if (isFixtureProblem(result)) return 'unresolvable';

    const resolvedTemplate = resolveFixtureForPrompt(newFixture, format);
    const regressions = await findRegressions(ruleId, format, allSoFar, fixtures);
    await agent.invoke(ruleId, format, requirement, newFixture, allSoFar, regressions, fixtures, resolvedTemplate);
    await RuleCatalog.refresh();

    result = await validateRequirement(ruleId, format, requirement, newFixture);
    return result.passed ? 'implemented_after_escalation' : 'unresolvable';
}

function resolveFixtureForPrompt(fixture: GeneratedFixture, format: 'cfn' | 'terraform'): string | undefined {
    if (format === 'terraform') return undefined;

    try {
        const rawTemplate = buildCloudFormationTemplate(fixture.templateSnippet);
        const resolved = parseCfnTemplate(rawTemplate);
        return JSON.stringify(resolved.Resources, null, 2);
    } catch {
        return undefined;
    }
}

function isFixtureProblem(result: ValidationResult): boolean {
    return result.diagnostics.suggestedCause === 'fixture_missing_resource' || result.diagnostics.suggestedCause === 'fixture_parse_error' || result.diagnostics.suggestedCause === 'fixture_wrong_structure';
}

async function findRegressions(ruleId: string, format: 'cfn' | 'terraform', allSoFar: RuleRequirement[], fixtures: Map<string, GeneratedFixture>): Promise<ValidationResult[]> {
    const regressions: ValidationResult[] = [];
    for (const req of allSoFar) {
        const fixture = fixtures.get(req.id);
        if (!fixture) continue;
        const result = await validateRequirement(ruleId, format, req, fixture);
        if (!result.passed) regressions.push(result);
    }
    return regressions;
}

async function countPassing(ruleId: string, format: 'cfn' | 'terraform', requirements: RuleRequirement[], fixtures: Map<string, GeneratedFixture>): Promise<number> {
    let count = 0;
    for (const req of requirements) {
        const fixture = fixtures.get(req.id);
        if (!fixture) continue;
        const result = await validateRequirement(ruleId, format, req, fixture);
        if (result.passed) count++;
    }
    return count;
}

async function getFailedIds(ruleId: string, format: 'cfn' | 'terraform', requirements: RuleRequirement[], fixtures: Map<string, GeneratedFixture>): Promise<string[]> {
    const failed: string[] = [];
    for (const req of requirements) {
        const fixture = fixtures.get(req.id);
        if (!fixture) { failed.push(req.id); continue; }
        const result = await validateRequirement(ruleId, format, req, fixture);
        if (!result.passed) failed.push(req.id);
    }
    return failed;
}

function writeTestFile(rule: RuleEntry, ruleId: string, requirements: RuleRequirement[], fixtures: Map<string, GeneratedFixture>): string {
    const ruleClassName = extractClassName(rule.sourceLocation);
    const testFilePath = buildTestFilePath(rule.sourceLocation);
    const ruleImportPath = buildRelativeImport(testFilePath, rule.sourceLocation);
    const rulesDir = rule.sourceLocation.replace(/\/rules\/.*$/, '');
    const ruleBaseImportPath = buildRelativeImport(testFilePath, path.join(rulesDir, 'security-rule-base.ts'));

    const pairs = requirements.map(req => ({ requirement: req, fixture: fixtures.get(req.id)! })).filter(p => p.fixture);
    const flagCases = pairs.filter(p => p.requirement.expectedBehavior === 'flag');
    const passCases = pairs.filter(p => p.requirement.expectedBehavior === 'pass');

    const lines: string[] = [];
    lines.push(`import { describe, it, expect } from 'vitest';`);
    lines.push(`import ${ruleClassName} from '${ruleImportPath}';`);
    lines.push(`import type { Template } from 'cloudform-types';`);
    lines.push(`import type { Resource } from '${ruleBaseImportPath}';`);
    lines.push('');
    lines.push(`describe('${ruleClassName}', () => {`);
    lines.push(`    const rule = new ${ruleClassName}();`);
    lines.push(`    const stackName = 'test-stack';`);
    lines.push('');
    lines.push(`    describe('appliesTo', () => {`);
    lines.push(`        it('should apply to ${rule.applicableResourceTypes![0]}', () => {`);
    lines.push(`            expect(rule.appliesTo('${rule.applicableResourceTypes![0]}')).toBe(true);`);
    lines.push(`        });`);
    lines.push('');
    lines.push(`        it('should not apply to unrelated types', () => {`);
    lines.push(`            expect(rule.appliesTo('AWS::Unrelated::Resource')).toBe(false);`);
    lines.push(`        });`);
    lines.push(`    });`);
    lines.push('');
    lines.push(`    describe('evaluateResource', () => {`);

    if (flagCases.length > 0) {
        lines.push(`        describe('should flag', () => {`);
        for (const { requirement, fixture } of flagCases) {
            lines.push(...buildTestCase(ruleId, requirement, fixture, rule.applicableResourceTypes!));
        }
        lines.push(`        });`);
        if (passCases.length > 0) lines.push('');
    }

    if (passCases.length > 0) {
        lines.push(`        describe('should pass', () => {`);
        for (const { requirement, fixture } of passCases) {
            lines.push(...buildTestCase(ruleId, requirement, fixture, rule.applicableResourceTypes!));
        }
        lines.push(`        });`);
    }

    lines.push(`    });`);
    lines.push(`});`);
    lines.push('');

    fs.mkdirSync(path.dirname(testFilePath), { recursive: true });
    fs.writeFileSync(testFilePath, lines.join('\n'));
    return testFilePath;
}

function buildTestCase(ruleId: string, requirement: RuleRequirement, fixture: GeneratedFixture, applicableResourceTypes: string[]): string[] {
    const description = requirement.description.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const parsed = yamlParse(fixture.templateSnippet);
    const resources = parsed.Resources ?? parsed;
    const template = { Resources: resources };
    const templateLiteral = formatAsTypescript(template, 16);
    const targetLogicalId = findTargetResource(resources, applicableResourceTypes);

    const lines: string[] = [];
    lines.push('');
    lines.push(`            it('${description}', () => {`);
    lines.push(`                const template: Template = ${templateLiteral};`);
    lines.push(`                const resource = template.Resources!['${targetLogicalId}'] as Resource;`);
    lines.push(`                const result = rule.evaluateResource(stackName, template, resource);`);

    if (requirement.expectedBehavior === 'flag') {
        lines.push(`                expect(result).not.toBeNull();`);
        lines.push(`                expect(result!.check_id).toBe('${ruleId}');`);
    } else {
        lines.push(`                expect(result).toBeNull();`);
    }

    lines.push(`            });`);
    return lines;
}

function findTargetResource(resources: Record<string, any>, applicableResourceTypes: string[]): string {
    for (const [logicalId, resource] of Object.entries(resources)) {
        if (resource && typeof resource === 'object' && 'Type' in resource) {
            if (applicableResourceTypes.includes(resource.Type)) return logicalId;
        }
    }
    return Object.keys(resources)[0];
}

function extractClassName(sourceLocation: string): string {
    const content = fs.readFileSync(sourceLocation, 'utf-8');
    const match = content.match(/export\s+default\s+new\s+(\w+)/);
    if (match) return match[1];
    const classMatch = content.match(/export\s+class\s+(\w+)/);
    if (classMatch) return classMatch[1];
    return 'Rule';
}

function buildRelativeImport(fromFile: string, toFile: string): string {
    const relative = path.relative(path.dirname(fromFile), toFile);
    const withJsExtension = relative.replace(/\.ts$/, '.js');
    return withJsExtension.startsWith('.') ? withJsExtension : './' + withJsExtension;
}

function buildTestFilePath(sourceLocation: string): string {
    const repoRoot = srtRepoRoot();
    const relative = path.relative(repoRoot, sourceLocation);
    const parts = relative.replace('src/assess/scanning/security-matrix/rules/', '').replace(/\.ts$/, '.test.ts');
    return path.join(repoRoot, 'tests', 'core', 'scanners', 'srt', 'rules', parts);
}

function formatAsTypescript(obj: unknown, baseIndent: number): string {
    const json = JSON.stringify(obj, null, 4);
    const indentStr = ' '.repeat(baseIndent);
    return json.split('\n').map((line, i) => i === 0 ? line : indentStr + line).join('\n');
}
