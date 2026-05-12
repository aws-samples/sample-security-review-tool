import { FixtureGeneratorAgent } from '../agents/fixture-generator/agent.js';
import type { RuleEntry } from '../shared/rule-catalog/index.js';
import type { RuleRequirement, RequirementsSpec } from '../types/requirements.js';
import type { GeneratedFixture } from '../agents/fixture-generator/types.js';

export interface FixtureSet {
    requirement: RuleRequirement;
    fixture: GeneratedFixture;
}

export async function generateFixtures(spec: RequirementsSpec, rule: RuleEntry): Promise<FixtureSet[]> {
    const agent = new FixtureGeneratorAgent();
    const results: FixtureSet[] = [];

    for (const requirement of spec.requirements) {
        console.log(`  Generating fixture for ${requirement.id} (${requirement.category})...`);
        const fixture = await agent.invoke(requirement, rule, spec.format);
        results.push({ requirement, fixture });
    }

    return results;
}
