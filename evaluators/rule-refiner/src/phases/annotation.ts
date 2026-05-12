import { RuleAnnotationAgent } from '../agents/rule-annotation/agent.js';
import type { FixtureFormat } from '../shared/rule-catalog/index.js';

export async function annotateRule(ruleId: string, format: FixtureFormat): Promise<void> {
    console.log(`  Annotating rule ${ruleId}...`);
    await new RuleAnnotationAgent().invoke(ruleId, format);
}
