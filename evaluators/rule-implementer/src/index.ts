import * as os from 'os';
import * as fs from 'fs';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';
import { generateRequirements } from './phases/requirements.js';
import { scaffold } from './phases/scaffold.js';
import { generateTests } from './phases/tests.js';
import { implementRule } from './phases/implementation.js';
import { RuleContext } from './shared/fixture-paths.js';

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });

SrtLogger.initialize(logsFolderPath);
BedrockConfig.initialize('default', 'us-east-1');

async function main(): Promise<void> {
    const context = parseArgs(process.argv.slice(2));

    console.log(`\nImplementing rule ${context.ruleId} (${context.description})\n`);

    console.log('\nPhase 1: Requirements generation');
    const spec = await generateRequirements(context, { regenerate: false });
    console.log(`Phase 1 complete: Generated ${spec.requirements.length} requirements`);

    console.log('\nPhase 2: Scaffold');
    await scaffold(context, spec);

    console.log('\nPhase 3: Test generation');
    await generateTests(context.ruleId, context.service, spec);

    console.log(`\nPhase 4: Rule implementation`);
    await implementRule(spec, context.service);

    console.log(`\n✓ Done.`);
}

function parseArgs(argv: string[]): RuleContext {
    let ruleId: string | undefined;
    let service: string | undefined;
    let description: string | undefined;
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
            case '--service':
                service = consumeValue();
                break;
            case '--description':
                description = consumeValue();
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
    if (!service) throw new Error('--service is required');
    if (!description) throw new Error('--description is required');

    return new RuleContext(ruleId, service, description);
}

function printUsage(): void {
    console.log(`Usage:
  bun src/index.ts --rule <checkId> --service <service> --description <description> [--regenerate]

Options:
  --rule <checkId>        Rule ID (e.g. S3-001, DDB-002)
  --service <service>     Service folder name (e.g. s3, dynamodb, cloudfront)
  --description <desc>    Description of the rule
  --regenerate            Force regeneration of cached requirements
  -h, --help              Show this help message
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
