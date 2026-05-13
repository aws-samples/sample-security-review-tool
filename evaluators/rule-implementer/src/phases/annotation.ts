import { RuleAnnotationAgent } from '../agents/rule-annotator/agent.js';
import type { FixtureFormat } from '../shared/types/rule-catalog.js';

export async function annotateRule(ruleId: string, format: FixtureFormat): Promise<void> {
    console.log(`  Annotating rule ${ruleId}...`);
    await new RuleAnnotationAgent().invoke(ruleId, format);
}
