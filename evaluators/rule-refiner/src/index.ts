import * as os from 'os';
import * as fs from 'fs';
import type { FixtureFormat } from './shared/rule-catalog/index.js';
import { RuleCatalog } from './shared/rule-catalog/index.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';
import { rewriteDescription } from './phases/description.js';
import { generateRequirements } from './phases/requirements.js';
import { generateFixtures } from './phases/fixtures.js';
import { implementRule } from './phases/implementation.js';
import { generateFixScenarios } from './phases/fix-scenarios.js';
import { validateFixInstructions } from './phases/fix-validation.js';
import { generateTestFile } from './phases/test-generation.js';
import { annotateRule } from './phases/annotation.js';

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });
SrtLogger.initialize(logsFolderPath);

BedrockConfig.initialize('default', 'us-east-1');

async function main(): Promise<void> {
    const { ruleId, fixtureFormat, regenerate } = parseArgs(process.argv.slice(2));

    console.log(`\nRefining rule ${ruleId} (${fixtureFormat})\n`);

    // Phase 1: Rewrite description to positive requirement statement
    console.log('Phase 1: Description rewrite');
    await rewriteDescription(ruleId, fixtureFormat);

    // Phase 2: Generate requirements from the positive description
    console.log('\nPhase 2: Requirements generation');
    const spec = await generateRequirements(ruleId, fixtureFormat, { regenerate });
    console.log(`  Generated ${spec.requirements.length} requirements`);

    // Phase 3: Generate fixtures for each requirement
    console.log('\nPhase 3: Fixture generation');
    const rule = await RuleCatalog.find(ruleId, fixtureFormat);
    const fixtureSets = await generateFixtures(spec, rule);

    // Phase 4: Implement the rule to satisfy all requirements
    console.log('\nPhase 4: Rule implementation');
    const implResult = await implementRule(spec, fixtureSets);

    if (implResult.failed.length > 0) {
        console.log(`\n  WARNING: ${implResult.failed.length} requirements could not be satisfied: ${implResult.failed.join(', ')}`);
    }

    // Phase 5: Generate fix scenarios (multiple starting states per variant)
    console.log('\nPhase 5: Fix scenario generation');
    const variantScenarios = await generateFixScenarios(ruleId, fixtureFormat);
    const totalScenarios = variantScenarios.reduce((sum, vs) => sum + vs.scenarios.length, 0);
    console.log(`  Generated ${totalScenarios} scenarios across ${variantScenarios.length} variant(s)`);

    // Phase 6: Validate fix instructions against all scenarios
    console.log('\nPhase 6: Fix instruction validation');
    const fixResults = await validateFixInstructions(ruleId, fixtureFormat, variantScenarios);
    const allFixesPassed = fixResults.every(r => r.allPassed);
    if (!allFixesPassed) {
        console.log('  WARNING: Some fix instruction scenarios failed');
    }

    // Phase 7: Generate Vitest test file
    console.log('\nPhase 7: Test file generation');
    const testFilePath = await generateTestFile(spec, implResult.fixtures);

    // Phase 8: Annotate the rule with JSDoc
    console.log('\nPhase 8: Annotation');
    await annotateRule(ruleId, fixtureFormat);

    console.log(`\n✓ Done. Rule: ${rule.sourceLocation}`);
    console.log(`  Tests: ${testFilePath}`);
    console.log(`  Requirements: ${implResult.passed}/${implResult.totalRequirements} passing`);
    console.log(`  Fix validation: ${allFixesPassed ? 'all passed' : 'some failed'}`);
}

interface ParsedArgs {
    ruleId: string;
    fixtureFormat: FixtureFormat;
    regenerate: boolean;
}

const VALID_FIXTURE_FORMATS: FixtureFormat[] = ['cfn', 'cdk', 'terraform'];

function parseArgs(argv: string[]): ParsedArgs {
    let ruleId: string | undefined;
    let fixtureFormat: FixtureFormat | undefined;
    let regenerate = false;

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        const consumeValue = (): string => {
            const next = argv[i + 1];
            if (next === undefined) throw new Error(`Missing value for ${arg}`);
            i++;
            return next;
        };

        switch (arg) {
            case '--rule':
                ruleId = consumeValue();
                break;
            case '--type':
                fixtureFormat = consumeValue() as FixtureFormat;
                break;
            case '--regenerate':
                regenerate = true;
                break;
            case '-h':
            case '--help':
                printUsage();
                process.exit(0);
                break;
            default:
                throw new Error(`Unknown argument: ${arg}`);
        }
    }

    if (!ruleId) throw new Error('--rule is required');
    if (!fixtureFormat) throw new Error('--type is required');
    if (!VALID_FIXTURE_FORMATS.includes(fixtureFormat)) {
        throw new Error(`Invalid fixture type "${fixtureFormat}". Valid types: ${VALID_FIXTURE_FORMATS.join(', ')}`);
    }

    return { ruleId, fixtureFormat, regenerate };
}

function printUsage(): void {
    console.log(`Usage:
  bun src/index.ts --rule <checkId> --type <format> [--regenerate]

Options:
  --rule <checkId>    Rule ID to refine (e.g. S3-001)
  --type <format>     Fixture format: ${VALID_FIXTURE_FORMATS.join(', ')}
  --regenerate        Force regeneration of cached requirements
  -h, --help          Show this help message
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
