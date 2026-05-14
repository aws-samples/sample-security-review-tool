import { RequirementsGeneratorAgent } from '../agents/requirements-generator/agent.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';

export async function generateRequirements(ruleId: string, description: string, options: { regenerate: boolean }): Promise<RequirementsSpec> {
    console.log(`  Generating requirements for ${ruleId}...`);
    return await new RequirementsGeneratorAgent().invoke(ruleId, description, options);
}
