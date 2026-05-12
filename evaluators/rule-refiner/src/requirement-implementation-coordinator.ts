import { RuleCatalog } from './shared/rule-catalog/index.js';
import { validateRequirement } from './agents/requirement-implementation/requirement-validator.js';
import type { FixtureGeneratorAgent } from './agents/fixture-generator/agent.js';
import type { RequirementImplementationAgent } from './agents/requirement-implementation/agent.js';
import type { RequirementsSpec, RuleRequirement } from './types/requirements.js';
import type { GeneratedFixture, FixtureRegenerationContext } from './agents/fixture-generator/types.js';
import type { ValidationResult } from './agents/requirement-implementation/types.js';

const MAX_IMPL_RETRIES = 3;

export class RequirementImplementationCoordinator {
    private fixtures = new Map<string, GeneratedFixture>();

    constructor(private fixtureGenerator: FixtureGeneratorAgent, private implementationAgent: RequirementImplementationAgent) {}

    public async run(spec: RequirementsSpec): Promise<void> {
        const { ruleId, format, requirements } = spec;

        console.log(`  Implementing ${requirements.length} requirements for ${ruleId}...`);

        for (let i = 0; i < requirements.length; i++) {
            const requirement = requirements[i];
            const allSoFar = requirements.slice(0, i + 1);
            const outcome = await this.processRequirement(ruleId, format, requirement, allSoFar);

            switch (outcome) {
                case 'already_passing':
                    console.log(`    ✓ ${requirement.id} already passing`);
                    break;
                case 'implemented':
                    console.log(`    ✓ ${requirement.id} implemented`);
                    break;
                case 'implemented_after_escalation':
                    console.log(`    ✓ ${requirement.id} implemented (after fixture regeneration)`);
                    break;
                case 'fixture_was_wrong':
                    console.log(`    ✓ ${requirement.id} passing (fixture was regenerated)`);
                    break;
                case 'unresolvable':
                    console.log(`    ✗ ${requirement.id} unresolvable`);
                    break;
            }
        }

        const passCount = await this.countPassing(ruleId, format, requirements);
        console.log(`  Final state: ${passCount}/${requirements.length} requirements passing`);
    }

    private async processRequirement(ruleId: string, format: 'cfn' | 'terraform', requirement: RuleRequirement, allSoFar: RuleRequirement[]): Promise<string> {
        const rule = await RuleCatalog.find(ruleId, format);

        console.log(`  Generating fixture for ${requirement.id}: ${requirement.description}`);
        const fixture = await this.fixtureGenerator.invoke(requirement, rule, format);
        this.fixtures.set(requirement.id, fixture);

        let result = await validateRequirement(ruleId, format, requirement, fixture);
        if (result.passed) return 'already_passing';

        if (result.diagnostics.suggestedCause === 'fixture_missing_resource' || result.diagnostics.suggestedCause === 'fixture_parse_error') {
            return await this.escalate(ruleId, format, requirement, allSoFar, result);
        }

        for (let attempt = 0; attempt < MAX_IMPL_RETRIES; attempt++) {
            const regressions = attempt === 0 ? [] : await this.findRegressions(ruleId, format, allSoFar);

            await this.implementationAgent.invoke(ruleId, format, requirement, fixture, allSoFar, regressions, this.fixtures);
            await RuleCatalog.refresh();

            result = await validateRequirement(ruleId, format, requirement, fixture);
            if (result.passed && (await this.findRegressions(ruleId, format, allSoFar)).length === 0) {
                return 'implemented';
            }

            console.log(`    Attempt ${attempt + 1}: ${result.passed ? 'passed but regressions' : `failed (${result.diagnostics.suggestedCause})`}`);
        }

        return await this.escalate(ruleId, format, requirement, allSoFar, result);
    }

    private async escalate(ruleId: string, format: 'cfn' | 'terraform', requirement: RuleRequirement, allSoFar: RuleRequirement[], lastResult: ValidationResult): Promise<string> {
        console.log(`    Escalating: regenerating fixture for ${requirement.id}`);

        const rule = await RuleCatalog.find(ruleId, format);
        const regenerationContext: FixtureRegenerationContext = {
            previousFixture: this.fixtures.get(requirement.id)!.templateSnippet,
            failureDiagnostics: lastResult.diagnostics,
        };

        const newFixture = await this.fixtureGenerator.invoke(requirement, rule, format, regenerationContext);
        this.fixtures.set(requirement.id, newFixture);

        let result = await validateRequirement(ruleId, format, requirement, newFixture);
        if (result.passed) return 'fixture_was_wrong';

        if (result.diagnostics.suggestedCause !== 'rule_logic') {
            console.log(`    Regenerated fixture still has structural issues: ${result.diagnostics.suggestedCause}`);
            return 'unresolvable';
        }

        const regressions = await this.findRegressions(ruleId, format, allSoFar);
        await this.implementationAgent.invoke(ruleId, format, requirement, newFixture, allSoFar, regressions, this.fixtures);
        await RuleCatalog.refresh();

        result = await validateRequirement(ruleId, format, requirement, newFixture);
        if (result.passed) return 'implemented_after_escalation';

        return 'unresolvable';
    }

    private async findRegressions(ruleId: string, format: 'cfn' | 'terraform', allSoFar: RuleRequirement[]): Promise<ValidationResult[]> {
        const regressions: ValidationResult[] = [];
        for (const req of allSoFar) {
            const fixture = this.fixtures.get(req.id);
            if (!fixture) continue;
            const result = await validateRequirement(ruleId, format, req, fixture);
            if (!result.passed) regressions.push(result);
        }
        return regressions;
    }

    private async countPassing(ruleId: string, format: 'cfn' | 'terraform', requirements: RuleRequirement[]): Promise<number> {
        let count = 0;
        for (const req of requirements) {
            const fixture = this.fixtures.get(req.id);
            if (!fixture) continue;
            const result = await validateRequirement(ruleId, format, req, fixture);
            if (result.passed) count++;
        }
        return count;
    }
}
