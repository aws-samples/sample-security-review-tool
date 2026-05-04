import * as path from 'node:path';
import * as url from 'node:url';
import { bootstrapBedrock } from './shared/bedrock-bootstrap.js';
import { Orchestrator, type OrchestratorOptions } from './orchestrator.js';
import * as fs from 'fs/promises';
import type { CatalogFilter, FixtureFormat, RuleEntry } from './types.js';
import { RuleImplementationAssessmentAgent } from './agents/rule-implementation-assessment/agent.js';
import { RuleCatalog } from './shared/rule-catalog/index.js';
import { RuleImplementationFixAgent } from './agents/rule-implementation-fix/agent.js';

interface ParsedArgs {
    filter: CatalogFilter;
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));
    const rule = await getRuleImplementation(args.filter.checkId!);

    for (let i = 0; i < 3; i++) {
        console.log(`Assessing implementation for rule ${rule.checkId}, attempt ${i + 1}...`);

        const ruleImplementationAssessmentAgent = new RuleImplementationAssessmentAgent();
        const ruleImplementationFixAgent = new RuleImplementationFixAgent();
        const ruleBody = rule.ruleBody;
        const assessmentResult = await ruleImplementationAssessmentAgent.invoke(ruleBody);

        if (assessmentResult.issues.length === 0) return;

        await ruleImplementationFixAgent.invoke(rule, assessmentResult);
    }
}

async function getRuleImplementation(checkId: string): Promise<RuleEntry> {
    const catalog = new RuleCatalog();

    await catalog.load();

    const rule = catalog.find(checkId);

    if (!rule) throw new Error(`Rule with checkId ${checkId} not found in catalog.`);

    return rule;
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

// async function main(): Promise<void> {
//     const args = parseArgs(process.argv.slice(2));
//     bootstrapBedrock();

//     const moduleDir = path.dirname(url.fileURLToPath(import.meta.url));
//     const evaluatorRoot = path.resolve(moduleDir, '..');
//     const srtRepoRoot = path.resolve(moduleDir, '..', '..', '..');
//     const reportsDir = path.resolve(evaluatorRoot, 'reports');
//     const fixturesRoot = path.resolve(evaluatorRoot, 'fixtures');

//     const orchestrator = new Orchestrator(srtRepoRoot, reportsDir, fixturesRoot);
//     const options: OrchestratorOptions = {
//         filter: args.filter,
//         formats: args.formats.length > 0 ? args.formats : undefined,
//         phase1Only: args.phase1Only,
//         phase2Only: args.phase2Only,
//     };

//     const { markdownPath, jsonPath } = await orchestrator.run(options);
//     console.log(`\nReports written:`);
//     console.log(`  ${markdownPath}`);
//     console.log(`  ${jsonPath}`);
// }

// function parseArgs(argv: string[]): ParsedArgs {
//     const result: ParsedArgs = {
//         filter: {},
//         formats: [],
//         phase1Only: false,
//         phase2Only: false,
//     };

//     for (let i = 0; i < argv.length; i++) {
//         const arg = argv[i];
//         const consumeValue = (): string => {
//             const next = argv[i + 1];
//             if (next === undefined) throw new Error(`Missing value for ${arg}`);
//             i++;
//             return next;
//         };
//         switch (arg) {
//             case '--rule':
//                 result.filter.checkId = consumeValue();
//                 break;
//             case '--service':
//                 result.filter.service = consumeValue();
//                 break;
//             case '--format':
//                 result.formats = consumeValue().split(',').map(s => s.trim()) as FixtureFormat[];
//                 break;
//             case '--phase1-only':
//                 result.phase1Only = true;
//                 break;
//             case '--phase2-only':
//                 result.phase2Only = true;
//                 break;
//             case '-h':
//             case '--help':
//                 printUsage();
//                 process.exit(0);
//                 break;
//             default:
//                 throw new Error(`Unknown argument: ${arg}`);
//         }
//     }

//     return result;
// }

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
