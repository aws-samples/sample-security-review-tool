import * as os from 'os';
import * as fs from 'fs';
import type { FixtureFormat } from './shared/rule-catalog/index.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';
import { generateFixScenarios } from './phases/fix-scenarios.js';
import { validateFixInstructions } from './phases/fix-validation.js';

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });
SrtLogger.initialize(logsFolderPath);

BedrockConfig.initialize('default', 'us-east-1');

async function main(): Promise<void> {
    const { ruleId, fixtureFormat } = parseArgs(process.argv.slice(2));

    console.log(`\nValidating fix instructions for ${ruleId} (${fixtureFormat})\n`);

    console.log('Phase 1: Fix scenario generation');
    const variantScenarios = await generateFixScenarios(ruleId, fixtureFormat);
    const totalScenarios = variantScenarios.reduce((sum, vs) => sum + vs.scenarios.length, 0);
    console.log(`  Generated ${totalScenarios} scenarios across ${variantScenarios.length} variant(s)`);

    console.log('\nPhase 2: Fix instruction validation');
    const fixResults = await validateFixInstructions(ruleId, fixtureFormat, variantScenarios);
    const allPassed = fixResults.every(r => r.allPassed);

    if (allPassed) {
        console.log('\n✓ All fix instruction scenarios passed.');
    } else {
        const failedCount = fixResults.reduce((sum, r) => sum + r.scenarioResults.filter(s => !s.passed).length, 0);
        console.log(`\n✗ ${failedCount} scenario(s) failed.`);
    }
}

const VALID_FIXTURE_FORMATS: FixtureFormat[] = ['cfn', 'cdk', 'terraform'];

interface ParsedArgs {
    ruleId: string;
    fixtureFormat: FixtureFormat;
}

function parseArgs(argv: string[]): ParsedArgs {
    let ruleId: string | undefined;
    let fixtureFormat: FixtureFormat | undefined;

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

    return { ruleId, fixtureFormat };
}

function printUsage(): void {
    console.log(`Usage:
  bun src/index.ts --rule <checkId> --type <format>

Options:
  --rule <checkId>    Rule ID (e.g. S3-001, DDB-002)
  --type <format>     Format: ${VALID_FIXTURE_FORMATS.join(', ')}
  -h, --help          Show this help message
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
