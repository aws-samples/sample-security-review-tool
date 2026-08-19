import * as os from 'os';
import * as fs from 'fs';
import { SrtLogger } from '../../src/shared/logging/srt-logger.js';
import { bridgeStrandsLoggingToSrt } from '../../src/shared/logging/strands-log-bridge.js';
import { BedrockConfig } from '../../src/config/aws/bedrock-config.js';
import { RuleContext } from './shared/rule-context.js';
import { RuleLocator } from './shared/rule-locator.js';
import { BuildWorkflow } from './building/build-workflow.js';
import { RequirementsWorkflow } from './requirements/requirements-workflow.js';
import { ConversionWorkflow } from './converting/conversion-workflow.js';
import { ExerciseWorkflow } from './exercise/exercise-workflow.js';
import { RuleBuilderLogger } from './shared/logging/rule-builder-logger.js';

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });

SrtLogger.initialize(logsFolderPath);
bridgeStrandsLoggingToSrt();
BedrockConfig.initialize('default', 'us-east-1');

const logger = new RuleBuilderLogger();

interface ParsedArgs { ruleId?: string; legacyRuleId?: string; service?: string; description?: string; regenerate: boolean; isFullBuild: boolean; requirementsOnly?: boolean; }

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));
    if (args.legacyRuleId) {
        await convert(args);
    } else if (args.requirementsOnly) {
        await requirements(args);
    } else if (args.isFullBuild) {
        await build(args);
    } else {
        await exercise(args);
    }
}

async function convert(args: ParsedArgs): Promise<void> {
    await new ConversionWorkflow(args.legacyRuleId!).run({ regenerate: args.regenerate });
}

async function build(args: ParsedArgs): Promise<void> {
    const context = buildContext(args);
    logger.runStart(context.ruleId, context.description);
    await new BuildWorkflow(context).run({ regenerate: args.regenerate });
    logger.runComplete(context.ruleId);
}

function buildContext(args: ParsedArgs): RuleContext {
    if (args.service) return new RuleContext(args.ruleId!, args.service, args.description!);
    return new RuleLocator(args.ruleId!).locate();
}

async function requirements(args: ParsedArgs): Promise<void> {
    const context = buildContext(args);
    logger.runStart(context.ruleId, context.description);
    const spec = await new RequirementsWorkflow(context).run({ regenerate: true });
    logger.info(`${spec.requirements.length} requirements written to ${context.requirementsFilePath}`);
    logger.runComplete(context.ruleId);
}

async function exercise(args: ParsedArgs): Promise<void> {
    const context = new RuleLocator(args.ruleId!).locate();
    logger.runStart(context.ruleId, context.description);
    await new ExerciseWorkflow(context).run();
    logger.runComplete(context.ruleId);
}

function parseArgs(argv: string[]): ParsedArgs {
    let ruleId: string | undefined;
    let legacyRuleId: string | undefined;
    let service: string | undefined;
    let description: string | undefined;
    let regenerate = false;
    let requirementsOnly = false;

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
            case '--convert':
                legacyRuleId = consumeValue();
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
            case '--requirements':
                requirementsOnly = true;
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

    if (legacyRuleId) {
        if (ruleId || service || description) throw new Error('--convert reads the rule id, service, and description from the existing rule; do not pass --rule, --service, or --description alongside it');
        if (requirementsOnly) throw new Error('--requirements cannot be combined with --convert; pass --rule instead');
        return { legacyRuleId, regenerate, isFullBuild: false };
    }

    if (!ruleId) throw new Error('--rule is required');

    if (requirementsOnly) return { ruleId, service, description, regenerate, isFullBuild: false, requirementsOnly };

    const hasService = !!service;
    const hasDescription = !!description;
    if (hasService !== hasDescription) throw new Error('--service and --description must be provided together to build a rule; pass only --rule to exercise an existing rule');

    // --regenerate alone rebuilds an existing rule: its service and description come from requirements.json.
    const isFullBuild = (hasService && hasDescription) || regenerate;

    return { ruleId, service, description, regenerate, isFullBuild };
}

function printUsage(): void {
    console.log(`Usage:
  Build a rule (full 5-phase pipeline):
    bun src/index.ts --rule <checkId> --service <service> --description <description> [--regenerate]

  Convert a legacy rule (same 5-phase pipeline, details read from the existing rule):
    bun src/index.ts --convert <legacyCheckId> [--regenerate]

  Rebuild an existing rule (same 5-phase pipeline, details read from requirements.json):
    bun src/index.ts --rule <checkId> --regenerate

  Regenerate only the requirements specification (phase 1, nothing downstream):
    bun src/index.ts --rule <checkId> --requirements

  Exercise an existing rule (run its unit tests + remediation against existing fixtures):
    bun src/index.ts --rule <checkId>

Options:
  --rule <checkId>        Rule ID (e.g. S3-001, DDB-002, LAMBDA-004)
  --convert <checkId>     Legacy rule ID to convert (e.g. LAMBDA-013, API-GW-002). Cannot be combined
                          with --rule, --service, or --description.
  --service <service>     Service folder name (e.g. s3, dynamodb, lambda). Required only for a new rule.
  --description <desc>    Description of the rule. Required only for a new rule.
  --regenerate            Clear tests, control, and adapter files before running (keeps cached requirements)
  --requirements          Regenerate the requirements specification and stop. Service and description
                          come from the existing requirements.json unless --service and --description
                          are given.
  -h, --help              Show this help message

With only --rule, service and description are recovered from the rule's
requirements.json; fixtures are NOT regenerated.

With --convert, the legacy rule's service and description are read from its own
source. The description is restated as a requirement ("X-Ray tracing not enabled"
becomes "Lambda functions must have X-Ray tracing enabled"), saved, and used to
drive the build. Running --convert again resumes from that description and any
requirements, scaffolding, or tests already written. The legacy rule sources,
tests, and registrations are deleted once the new rule is implemented, before the
unit tests and remediation run.
`);
}

main().catch(error => {
    logger.error(error);
    process.exit(1);
});
