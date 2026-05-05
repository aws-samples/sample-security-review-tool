import type { FixtureFormat } from './types.js';
import { RuleImplementationAssessmentAgent } from './agents/rule-implementation-assessment/agent.js';
import { RuleImplementationFixAgent } from './agents/rule-implementation-fix/agent.js';
import { RuleAnnotationAgent } from './agents/rule-annotation/agent.js';

interface ParsedArgs {
    ruleId: string;
    fixtureFormat: FixtureFormat;
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));
    const { ruleId, fixtureFormat } = args;
    const maxAttempts = 5;

    let lastLimitations: string[] = [];

    for (let i = 0; i < maxAttempts; i++) {
        console.log(`Assessing implementation for rule ${ruleId} (${fixtureFormat}), iteration ${i + 1}...`);

        const assessmentAgent = new RuleImplementationAssessmentAgent();
        const assessmentResult = await assessmentAgent.invoke(ruleId, fixtureFormat);

        lastLimitations = assessmentResult.limitations;

        if (assessmentResult.issues.length === 0) break;

        console.log(`${assessmentResult.issues.length} issues found for rule ${ruleId}:`);

        const fixAgent = new RuleImplementationFixAgent();
        await fixAgent.invoke(ruleId, fixtureFormat, assessmentResult);
    }

    console.log(`Annotating rule ${ruleId} with documentation comment...`);
    const annotationAgent = new RuleAnnotationAgent();
    await annotationAgent.invoke(ruleId, fixtureFormat, lastLimitations);
}

const VALID_FIXTURE_FORMATS: FixtureFormat[] = ['cfn', 'cdk', 'terraform'];

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
  --rule <checkId>   Rule ID to refine (e.g. DOCDB-003)
  --type <format>    Fixture format: ${VALID_FIXTURE_FORMATS.join(', ')}
  -h, --help         Show this help message
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
