import * as path from 'node:path';
import * as url from 'node:url';
import { Evaluator } from './evaluator.js';
import type { CatalogFilter, FixtureFormat, Scanner } from '../../shared/rule-catalog/src/index.js';

interface ParsedArgs {
    targetProjectPath: string | null;
    filter: CatalogFilter;
    formats: FixtureFormat[];
    regenerate: boolean;
    concurrency: number;
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));

    const moduleDir = path.dirname(url.fileURLToPath(import.meta.url));
    const evaluatorRoot = path.resolve(moduleDir, '..');
    const srtRepoRoot = path.resolve(moduleDir, '..', '..', '..');
    const reportsDir = path.resolve(evaluatorRoot, 'reports');
    const fixturesRoot = path.resolve(evaluatorRoot, 'fixtures');

    const evaluator = new Evaluator(srtRepoRoot, reportsDir, fixturesRoot);

    if (args.targetProjectPath) {
        const { markdownPath, jsonPath } = await evaluator.evaluateProject(args.targetProjectPath);
        console.log(`\nReports written:`);
        console.log(`  ${markdownPath}`);
        console.log(`  ${jsonPath}`);
        return;
    }

    const { markdownPath, jsonPath, coveragePath } = await evaluator.evaluateFixtures({
        filter: args.filter,
        formats: args.formats,
        regenerate: args.regenerate,
        concurrency: args.concurrency,
    });
    console.log(`\nReports written:`);
    console.log(`  ${coveragePath}`);
    console.log(`  ${markdownPath}`);
    console.log(`  ${jsonPath}`);
}

function parseArgs(argv: string[]): ParsedArgs {
    const result: ParsedArgs = {
        targetProjectPath: null,
        filter: {},
        formats: [],
        regenerate: false,
        concurrency: 3,
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
            case '--source':
                result.filter.scanner = consumeValue() as Scanner;
                break;
            case '--service':
                result.filter.service = consumeValue();
                break;
            case '--format':
                result.formats = consumeValue().split(',').map(s => s.trim()) as FixtureFormat[];
                break;
            case '--regenerate':
                result.regenerate = true;
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
                if (arg.startsWith('-')) {
                    throw new Error(`Unknown flag: ${arg}`);
                }
                if (result.targetProjectPath) {
                    throw new Error(`Unexpected positional argument: ${arg}`);
                }
                result.targetProjectPath = path.resolve(arg);
                break;
        }
    }
    return result;
}

function printUsage(): void {
    console.log(`Usage:
  bun src/index.ts                           # evaluate every rule (fixture mode)
  bun src/index.ts --rule <checkId>          # single rule
  bun src/index.ts --source <scanner>        # security-matrix | checkov | bandit | semgrep
  bun src/index.ts --service <name>          # e.g. s3, rds, lambda
  bun src/index.ts --format <list>           # comma-sep: cfn,cdk,python,javascript,go,java,yaml
  bun src/index.ts --regenerate              # force regeneration of cached fixtures
  bun src/index.ts --concurrency <n>         # parallel fixture evaluations (default 3)
  bun src/index.ts /path/to/project          # legacy: evaluate findings in an existing project
`);
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
