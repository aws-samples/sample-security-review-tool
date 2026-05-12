import { DescriptionRewriterAgent } from '../agents/description-rewriter/agent.js';
import type { FixtureFormat } from '../shared/rule-catalog/index.js';

export async function rewriteDescription(ruleId: string, format: FixtureFormat): Promise<void> {
    console.log(`  Rewriting description for ${ruleId}...`);
    await new DescriptionRewriterAgent().invoke(ruleId, format);
}
