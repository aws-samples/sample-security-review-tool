import * as path from 'node:path';
import * as url from 'node:url';
import { RuleImplEvaluator } from './evaluator.js';
import { bootstrapBedrock } from './bedrock-bootstrap.js';
import type { CatalogFilter } from '../../shared/rule-catalog/src/index.js';

interface ParsedArgs {
    filter: CatalogFilter;
    changedOnly: boolean;
    concurrency: number;
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));
    bootstrapBedrock();

    const moduleDir = path.dirname(url.fileURLToPath(import.meta.url));
    const evaluatorRoot = path.resolve(moduleDir, '..');
    const srtRepoRoot = path.resolve(moduleDir, '..', '..', '..');
    const reportsDir = path.resolve(evaluatorRoot, 'reports');

    const evaluator = new RuleImplEvaluator(srtRepoRoot, reportsDir);
    const { markdownPath, jsonPath } = await evaluator.evaluate({
        filter: args.filter,
        changedOnly: args.changedOnly,
        concurrency: args.concurrency,
    });
    console.log(`\nReports written:`);
    console.log(`  ${markdownPath}`);
    console.log(`  ${jsonPath}`);
}

function parseArgs(argv: string[]): ParsedArgs {
    const result: ParsedArgs = {
        filter: {},
        changedOnly: false,
        concurrency: 4,
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
            case '--changed':
                result.changedOnly = true;
                break;
            case '--concurrency': {
                const value = Number(consumeValue());
                if (!Number.isFinite(value) || value < 1) {
                    throw new Error('--concurrency must be a positive integer');
                }
                result.concurrency = Math.floor(value);
                break;
            }
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
  bun src/index.ts                           # review every security-matrix rule
  bun src/index.ts --rule <checkId>          # single rule
  bun src/index.ts --service <name>          # one service (e.g. s3, rds)
  bun src/index.ts --changed                 # only rules whose source hash changed since last report
  bun src/index.ts --concurrency <n>         # parallel reviews (default 4)
`);
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
