import * as os from 'os';
import * as fs from 'fs';
import { SrtLogger } from '../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../src/config/aws/bedrock-config.js';
import { RequirementsWorkflow } from './requirements/requirements-workflow.js';
import { ScaffoldingWorkflow } from './scaffolding/scaffolding-workflow.js';
import { ImplementationWorkflow } from './implementation/implementation-workflow.js';
import { RemediationWorkflow } from './remediation/remediation-workflow.js';
import { RuleContext } from './shared/rule-context.js';
import { FixtureWorkflow } from './fixtures/fixture-workflow.js';
import { RuleBuilderLogger } from './shared/logging/rule-builder-logger.js';

const PHASE_COUNT = 5;

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });

SrtLogger.initialize(logsFolderPath);
BedrockConfig.initialize('default', 'us-east-1');

const logger = new RuleBuilderLogger();

async function main(): Promise<void> {
    const context = parseArgs(process.argv.slice(2));

    logger.runStart(context.ruleId, context.description);

    logger.phaseStart(1, PHASE_COUNT, 'Requirements');
    const requirements = await new RequirementsWorkflow(context).run({ regenerate: false });
    logger.phaseComplete(`${requirements.requirements.length} requirements generated`);

    logger.phaseStart(2, PHASE_COUNT, 'Scaffolding');
    new ScaffoldingWorkflow(context).run(requirements);
    logger.phaseComplete('control file + adapters scaffolded');

    logger.phaseStart(3, PHASE_COUNT, 'Implementation');
    await new ImplementationWorkflow(context).run(requirements);
    logger.phaseComplete(`${context.ruleId} implemented`);

    logger.phaseStart(4, PHASE_COUNT, 'Fixtures');
    await new FixtureWorkflow(context).run();
    logger.phaseComplete('fixtures generated');

    logger.phaseStart(5, PHASE_COUNT, 'Remediation');
    await new RemediationWorkflow(context).run();
    logger.phaseComplete('remediations tested');

    logger.runComplete(context.ruleId);
}

function clearGeneratedArtifacts(context: RuleContext): void {
    logger.info(`Regenerating ${context.ruleId}: clearing tests, control, and adapter files`);
    fs.rmSync(context.testsFolderPath, { recursive: true, force: true });
    fs.rmSync(context.ruleControlFilePath, { force: true });
    fs.rmSync(context.ruleAdapterBaseFilePath, { force: true });
    fs.rmSync(context.ruleAdapterCfnFilePath, { force: true });
    fs.rmSync(context.ruleAdapterTfFilePath, { force: true });
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
  --regenerate            Clear tests, control, and adapter files before running (keeps cached requirements)
  -h, --help              Show this help message
`);
}

main().catch(error => {
    logger.error(error.message);
    process.exit(1);
});
