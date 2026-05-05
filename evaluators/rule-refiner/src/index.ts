import type { CatalogFilter } from './types.js';
import { RuleImplementationAssessmentAgent } from './agents/rule-implementation-assessment/agent.js';
import { RuleImplementationFixAgent } from './agents/rule-implementation-fix/agent.js';
import { RuleAnnotationAgent } from './agents/rule-annotation/agent.js';

interface ParsedArgs {
    filter: CatalogFilter;
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));
    const ruleId = args.filter.checkId!;
    const maxAttempts = 5;

    let lastLimitations: string[] = [];

    for (let i = 0; i < maxAttempts; i++) {
        console.log(`Assessing implementation for rule ${ruleId}, iteration ${i + 1}...`);

        const assessmentAgent = new RuleImplementationAssessmentAgent();
        const assessmentResult = await assessmentAgent.invoke(ruleId);

        lastLimitations = assessmentResult.limitations;

        if (assessmentResult.issues.length === 0) break;

        console.log(`${assessmentResult.issues.length} issues found for rule ${ruleId}:`);

        const fixAgent = new RuleImplementationFixAgent();
        await fixAgent.invoke(ruleId, assessmentResult);
    }

    console.log(`Annotating rule ${ruleId} with documentation comment...`);
    const annotationAgent = new RuleAnnotationAgent();
    await annotationAgent.invoke(ruleId, lastLimitations);
}

function parseArgs(argv: string[]): ParsedArgs {
    const result: ParsedArgs = {
        filter: {}
    };

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
                result.filter.checkId = consumeValue();
                break;
            case '--service':
                result.filter.service = consumeValue();
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

    return result;
}

function printUsage(): void {
    console.log(`Usage:
  bun src/index.ts --rule <checkId>             # refine a single rule
  bun src/index.ts --service <name>             # all rules for a service
  bun src/index.ts --format cfn,cdk             # limit to specific formats
  bun src/index.ts --phase1-only                # skip fix guidance evaluation
  bun src/index.ts --phase2-only                # skip detection logic evaluation
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
