import * as os from 'os';
import * as fs from 'fs';
import type { FixtureFormat } from './shared/types/rule-catalog.js';
import { RuleCatalog } from './shared/rule-catalog/index.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';
import { rewriteDescription } from './phases/description.js';
import { generateRequirements } from './phases/requirements.js';
import { generateTests } from './phases/tests.js';
import { implementRule } from './phases/implementation.js';
import { annotateRule } from './phases/annotation.js';

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });

SrtLogger.initialize(logsFolderPath);
BedrockConfig.initialize('default', 'us-east-1');

async function main(): Promise<void> {
    const { ruleId, fixtureFormat, regenerate } = parseArgs(process.argv.slice(2));

    console.log(`\nImplementing rule ${ruleId} (${fixtureFormat})\n`);

    console.log('Phase 1: Description generation');
    await rewriteDescription(ruleId, fixtureFormat);

    console.log('\nPhase 2: Requirements generation');
    const spec = await generateRequirements(ruleId, fixtureFormat, { regenerate });
    console.log(`  Generated ${spec.requirements.length} requirements`);

    console.log('\nPhase 3: Test generation');
    const fixtureSets = await generateTests(ruleId, fixtureFormat, spec);

    return;

    console.log('\nPhase 4: Rule implementation');
    const implResult = await implementRule(spec, fixtureSets);

    if (implResult.failed.length > 0) {
        console.log(`\n  WARNING: ${implResult.failed.length} requirements could not be satisfied: ${implResult.failed.join(', ')}`);
    }

    console.log('\nPhase 5: Annotation');
    await annotateRule(ruleId, fixtureFormat);

    console.log(`\n✓ Done.`);
    //console.log(`  Rule: ${rule.sourceLocation}`);
    console.log(`  Tests: ${implResult.testFilePath}`);
    console.log(`  Requirements: ${implResult.passed}/${implResult.totalRequirements} passing`);
}

const VALID_FIXTURE_FORMATS: FixtureFormat[] = ['cfn', 'cdk', 'terraform'];

interface ParsedArgs {
    ruleId: string;
    fixtureFormat: FixtureFormat;
    regenerate: boolean;
}

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
  --rule <checkId>    Rule ID (e.g. S3-001, DDB-002)
  --type <format>     Format: ${VALID_FIXTURE_FORMATS.join(', ')}
  --regenerate        Force regeneration of cached requirements
  -h, --help          Show this help message
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
