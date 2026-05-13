import { FixtureGeneratorAgent } from '../agents/test-generator/agent.js';
import type { FixtureFormat } from '../shared/types/rule-catalog.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import type { FixtureSet } from '../shared/types/fixtures.js';

const MAX_CONCURRENCY = 3;

export async function generateTests(ruleId: string, fixtureFormat: FixtureFormat, spec: RequirementsSpec): Promise<FixtureSet[]> {
    console.log(`  Generating ${spec.requirements.length} fixtures (${MAX_CONCURRENCY} at a time)...`);

    const results: FixtureSet[] = [];

    for (let i = 0; i < spec.requirements.length; i += MAX_CONCURRENCY) {
        const batch = spec.requirements.slice(i, i + MAX_CONCURRENCY);

        const batchResults = await Promise.all(batch.map(async (requirement) => {
            const agent = new FixtureGeneratorAgent();
            const fixture = await agent.invoke(requirement, ruleId, fixtureFormat);
            console.log(`    ✓ ${requirement.id} (${requirement.category})`);
            return { requirement, fixture };
        }));

        results.push(...batchResults);
    }

    return results;
}
