import { RequirementsGeneratorAgent } from '../agents/requirements-generator/agent.js';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';

export async function generateRequirements(context: RuleContext, options: { regenerate: boolean }): Promise<RequirementsSpec> {
    return await new RequirementsGeneratorAgent().invoke(context, options);
}
