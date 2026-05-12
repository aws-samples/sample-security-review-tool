import { RuleCatalog } from '../shared/rule-catalog/index.js';
import { validateRequirement } from '../agents/requirement-implementation/requirement-validator.js';
import { RequirementImplementationAgent } from '../agents/requirement-implementation/agent.js';
import { FixtureGeneratorAgent } from '../agents/fixture-generator/agent.js';
import { buildCloudFormationTemplate } from '../agents/requirement-implementation/template-builder.js';
import { parseCfnTemplate } from '../../../../src/assess/scanning/security-matrix/cfn-utils.js';
import type { RequirementsSpec, RuleRequirement } from '../types/requirements.js';
import type { GeneratedFixture, FixtureRegenerationContext } from '../agents/fixture-generator/types.js';
import type { ValidationResult } from '../agents/requirement-implementation/types.js';
import type { FixtureSet } from './fixtures.js';

const MAX_RETRIES = 2;

export interface ImplementationResult {
    totalRequirements: number;
    passed: number;
    failed: string[];
    fixtures: Map<string, GeneratedFixture>;
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

    return { totalRequirements: requirements.length, passed: passCount, failed: failedIds, fixtures };
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
