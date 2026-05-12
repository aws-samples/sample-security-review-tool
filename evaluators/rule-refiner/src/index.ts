import * as os from 'os';
import * as fs from 'fs';
import type { FixtureFormat } from './shared/rule-catalog/index.js';
import { RuleFixtureAgent } from './agents/rule-fixture/agent.js';
import { FixInstructionValidationAgent } from './agents/fix-instruction-validation/agent.js';
import { FixInstructionUpdaterAgent } from './agents/fix-instruction-updater/agent.js';
import { FixtureGeneratorAgent } from './agents/fixture-generator/agent.js';
import { RequirementImplementationAgent } from './agents/requirement-implementation/agent.js';
import { RequirementsGeneratorAgent } from './agents/requirements-generator/agent.js';
import { DescriptionRewriterAgent } from './agents/description-rewriter/agent.js';
import { RuleAnnotationAgent } from './agents/rule-annotation/agent.js';
import { RequirementImplementationCoordinator } from './requirement-implementation-coordinator.js';
import { FixInstructionRefinementCoordinator } from './fix-instruction-refinement-coordinator.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });
SrtLogger.initialize(logsFolderPath);

BedrockConfig.initialize('default', 'us-east-1');

interface ParsedArgs {
    ruleId: string;
    fixtureFormat: FixtureFormat;
    regenerate: boolean;
}

async function main(): Promise<void> {
    const { ruleId, fixtureFormat, regenerate } = parseArgs(process.argv.slice(2));

    console.log(`Refining rule ${ruleId} (${fixtureFormat})...`);

    await new DescriptionRewriterAgent().invoke(ruleId, fixtureFormat);

    const spec = await new RequirementsGeneratorAgent().invoke(ruleId, fixtureFormat, { regenerate });

    const implementationCoordinator = new RequirementImplementationCoordinator(
        new FixtureGeneratorAgent(),
        new RequirementImplementationAgent()
    );
    await implementationCoordinator.run(spec);

    const fixInstructionCoordinator = new FixInstructionRefinementCoordinator(
        new RuleFixtureAgent(),
        new FixInstructionValidationAgent(),
        new FixInstructionUpdaterAgent()
    );
    await fixInstructionCoordinator.run(ruleId, fixtureFormat);

    await new RuleAnnotationAgent().invoke(ruleId, fixtureFormat);
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
  --rule <checkId>    Rule ID to refine (e.g. DOCDB-003)
  --type <format>     Fixture format: ${VALID_FIXTURE_FORMATS.join(', ')}
  --regenerate        Force regeneration of cached requirements
  -h, --help          Show this help message
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
