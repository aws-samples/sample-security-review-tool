import * as fs from 'fs';
import { FixScenarioGeneratorAgent } from '../agents/fix-scenario-generator/agent.js';
import { RuleCatalog } from '../shared/rule-catalog/index.js';
import { extractVariants } from '../shared/variant-extractor.js';
import type { FixScenario } from '../agents/fix-scenario-generator/agent.js';
import type { FixtureFormat } from '../shared/rule-catalog/index.js';
import type { FindingVariant } from '../types.js';

export interface VariantScenarios {
    variant: FindingVariant;
    scenarios: FixScenario[];
}

export async function generateFixScenarios(ruleId: string, format: FixtureFormat): Promise<VariantScenarios[]> {
    const rule = await RuleCatalog.find(ruleId, format);
    const ruleSource = fs.readFileSync(rule.sourceLocation, 'utf-8');
    const variants = extractVariants(ruleSource);
    const agent = new FixScenarioGeneratorAgent();
    const agentFormat = format === 'terraform' ? 'terraform' as const : 'cfn' as const;

    if (variants.length === 0) {
        const defaultVariant: FindingVariant = { variantId: 'default', fixGuidance: rule.fixGuidance ?? '', label: 'default' };
        console.log(`  Generating fix scenarios for default variant...`);
        const scenarios = await agent.invoke(defaultVariant.fixGuidance, ruleSource, rule.applicableResourceTypes ?? [], agentFormat);
        return [{ variant: defaultVariant, scenarios }];
    }

    const results: VariantScenarios[] = [];
    for (const variant of variants) {
        console.log(`  Generating fix scenarios for variant ${variant.variantId}: ${variant.label}...`);
        const scenarios = await agent.invoke(variant.fixGuidance, ruleSource, rule.applicableResourceTypes ?? [], agentFormat);
        results.push({ variant, scenarios });
    }

    return results;
}
