import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { FixInstructionValidationAgent } from '../agents/fix-instruction-validation/agent.js';
import { FixInstructionUpdaterAgent } from '../agents/fix-instruction-updater/agent.js';
import { RuleCatalog } from '../shared/rule-catalog/index.js';
import { extractVariants } from '../shared/variant-extractor.js';
import type { FixtureFormat } from '../shared/rule-catalog/index.js';
import type { FixInstructionValidationResult } from '../agents/types.js';
import type { VariantScenarios } from './fix-scenarios.js';
import type { FixScenario } from '../agents/fix-scenario-generator/agent.js';

const MAX_RETRIES = 5;

export interface FixValidationResult {
    variantId: string;
    scenarioResults: ScenarioResult[];
    allPassed: boolean;
}

interface ScenarioResult {
    scenarioId: string;
    passed: boolean;
    details?: string;
}

export async function validateFixInstructions(ruleId: string, format: FixtureFormat, variantScenarios: VariantScenarios[]): Promise<FixValidationResult[]> {
    const validationAgent = new FixInstructionValidationAgent();
    const updaterAgent = new FixInstructionUpdaterAgent();
    const results: FixValidationResult[] = [];

    for (const { variant, scenarios } of variantScenarios) {
        console.log(`  Validating fix instructions for variant: ${variant.variantId}`);
        const scenarioResults = await validateVariantScenarios(ruleId, format, variant, scenarios, validationAgent, updaterAgent);
        const allPassed = scenarioResults.every(r => r.passed);
        results.push({ variantId: variant.variantId, scenarioResults, allPassed });

        if (allPassed) {
            console.log(`    ✓ All scenarios passed`);
        } else {
            const failed = scenarioResults.filter(r => !r.passed);
            console.log(`    ✗ ${failed.length} scenario(s) failed`);
        }
    }

    return results;
}

async function validateVariantScenarios(ruleId: string, format: FixtureFormat, variant: { variantId: string; fixGuidance: string; label: string }, scenarios: FixScenario[], validationAgent: FixInstructionValidationAgent, updaterAgent: FixInstructionUpdaterAgent): Promise<ScenarioResult[]> {
    let previousNewIssues: string | null = null;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        const scenarioResults: ScenarioResult[] = [];
        let allPassed = true;
        let failedResult: FixInstructionValidationResult | undefined;

        for (const scenario of scenarios) {
            const fixtureDir = writeScenarioToDisk(scenario, format);

            try {
                const result = await validationAgent.invoke({
                    fixtureDir,
                    checkId: ruleId,
                    variantId: variant.variantId,
                    formatVariant: format === 'cdk' ? 'cdk' : format,
                    fixGuidanceOverride: variant.fixGuidance,
                });

                const passed = result.scanFoundIssue && result.fixResolved && result.newIssuesIntroduced.length === 0;
                scenarioResults.push({ scenarioId: scenario.scenarioId, passed, details: result.failureDetails });

                if (!passed) {
                    allPassed = false;
                    failedResult = result;
                }
            } finally {
                fs.rmSync(fixtureDir, { recursive: true, force: true });
            }
        }

        if (allPassed) return scenarioResults;

        if (!failedResult) return scenarioResults;

        const currentNewIssues = failedResult.newIssuesIntroduced.sort().join(',');
        if (currentNewIssues === previousNewIssues) {
            console.log(`      Repeated identical issues — stopping retry loop`);
            return scenarioResults;
        }
        previousNewIssues = currentNewIssues;

        if (attempt === MAX_RETRIES - 1) {
            console.log(`      Failed after ${MAX_RETRIES} attempts`);
            return scenarioResults;
        }

        console.log(`      Attempt ${attempt + 1} failed — updating fix instructions...`);
        const failedScenario = scenarios.find(s => scenarioResults.find(r => r.scenarioId === s.scenarioId && !r.passed));
        const tempDir = writeScenarioToDisk(failedScenario!, format);
        try {
            await updaterAgent.invoke(ruleId, format, variant, failedResult, tempDir);
        } finally {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }

        await RuleCatalog.refresh();
        const refreshedRule = await RuleCatalog.find(ruleId, format);
        const refreshedVariants = extractVariants(refreshedRule.ruleBody);
        const refreshedVariant = refreshedVariants.find(v => v.variantId === variant.variantId);
        variant.fixGuidance = refreshedVariant?.fixGuidance ?? refreshedRule.fixGuidance;
    }

    return scenarios.map(s => ({ scenarioId: s.scenarioId, passed: false, details: 'Exhausted retries' }));
}

function writeScenarioToDisk(scenario: FixScenario, format: FixtureFormat): string {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fix-scenario-'));

    if (format === 'terraform') {
        fs.writeFileSync(path.join(tmpDir, 'main.tf'), scenario.templateSnippet);
        fs.writeFileSync(path.join(tmpDir, 'providers.tf'), 'provider "aws" { region = "us-east-1" }\n');
    } else {
        const templateContent = scenario.templateSnippet.includes('AWSTemplateFormatVersion')
            ? scenario.templateSnippet
            : `AWSTemplateFormatVersion: "2010-09-09"\nResources:\n${indentYaml(scenario.templateSnippet, 2)}`;
        fs.writeFileSync(path.join(tmpDir, 'template.yaml'), templateContent);
    }

    return tmpDir;
}

function indentYaml(yaml: string, spaces: number): string {
    const indent = ' '.repeat(spaces);
    return yaml.split('\n').map(line => indent + line).join('\n');
}
