import { RequirementsGeneratorAgent } from '../agents/requirements-generator/agent.js';
import type { FixtureFormat } from '../shared/types/rule-catalog.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';

export async function generateRequirements(ruleId: string, format: FixtureFormat, options: { regenerate: boolean }): Promise<RequirementsSpec> {
    console.log(`  Generating requirements for ${ruleId}...`);
    return await new RequirementsGeneratorAgent().invoke(ruleId, format, options);
}
