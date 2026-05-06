import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import type { FixtureFormat } from './types.js';
import { RuleImplementationAssessmentAgent } from './agents/rule-implementation-assessment/agent.js';
import { RuleImplementationFixAgent } from './agents/rule-implementation-fix/agent.js';
import { RuleAnnotationAgent } from './agents/rule-annotation/agent.js';
import { RuleFixtureAgent } from './agents/rule-fixture/agent.js';
import { writeFixtureFiles } from './agents/rule-fixture/fixture-writer.js';
import { FixInstructionValidationAgent } from './agents/fix-instruction-validation/agent.js';
import { FixInstructionUpdaterAgent } from './agents/fix-instruction-updater/agent.js';
import { RuleCatalog } from './shared/rule-catalog/index.js';
import { extractVariants } from './shared/variant-extractor.js';
import { fixtureDirFor, srtRepoRoot } from './shared/fixture-paths.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';

const logsFolderPath = path.join(os.homedir(), '.srt', 'logs');
fs.mkdirSync(logsFolderPath, { recursive: true });
SrtLogger.initialize(logsFolderPath);

interface ParsedArgs {
    ruleId: string;
    fixtureFormat: FixtureFormat;
    skipAssessment: boolean;
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));
    const { ruleId, fixtureFormat, skipAssessment } = args;

    if (!skipAssessment) {
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

    await validateFixInstructions(ruleId, fixtureFormat);
}

async function validateFixInstructions(ruleId: string, fixtureFormat: FixtureFormat): Promise<void> {
    const fixturesRoot = path.join(srtRepoRoot(), 'evaluators', 'rule-refiner', 'fixtures');
    const maxRetries = 5;

    console.log(`Generating test fixtures for rule ${ruleId}...`);
    const fixtureAgent = new RuleFixtureAgent();
    const fixtureOutput = await fixtureAgent.invoke(ruleId, fixtureFormat);

    await RuleCatalog.refresh();
    const rule = await RuleCatalog.find(ruleId, fixtureFormat);

    for (const fixture of fixtureOutput.fixtures) {
        const dir = fixtureDirFor(fixturesRoot, 'security-matrix', fixture.formatVariant, rule.checkId, fixture.variantId);
        console.log(`  Writing fixture: ${fixture.formatVariant}/${fixture.variantId}`);
        await writeFixtureFiles(dir, fixture.files);
    }

    const variants = extractVariants(rule.ruleBody);
    const effectiveVariants = variants.length > 0
        ? variants
        : [{ variantId: 'default', fixGuidance: rule.fixGuidance, label: '' }];

    const validationAgent = new FixInstructionValidationAgent();
    const updaterAgent = new FixInstructionUpdaterAgent();

    for (const variant of effectiveVariants) {
        const formatVariants = fixtureFormat === 'cfn' || fixtureFormat === 'cdk'
            ? ['cfn', 'cdk'] as const
            : [fixtureFormat] as const;

        for (const formatVariant of formatVariants) {
            console.log(`  Validating fix instructions: ${variant.variantId}/${formatVariant}`);

            for (let attempt = 0; attempt < maxRetries; attempt++) {
                const fixtureDir = fixtureDirFor(fixturesRoot, 'security-matrix', formatVariant, rule.checkId, variant.variantId);

                const result = await validationAgent.invoke({
                    fixtureDir,
                    checkId: rule.checkId,
                    variantId: variant.variantId,
                    formatVariant,
                });

                if (!result.scanFoundIssue) {
                    console.warn(`    Fixture did not trigger rule — skipping`);
                    break;
                }

                if (result.fixResolved && result.newIssuesIntroduced.length === 0) {
                    console.log(`    PASSED (attempt ${attempt + 1})`);
                    break;
                }

                if (attempt === maxRetries - 1) {
                    console.warn(`    FAILED after ${maxRetries} attempts: ${result.failureDetails}`);
                    break;
                }

                console.log(`    Attempt ${attempt + 1} failed: ${result.failureDetails}. Updating fix instructions...`);
                await updaterAgent.invoke(ruleId, fixtureFormat, variant, result);
                await RuleCatalog.refresh();
            }
        }
    }
}

const VALID_FIXTURE_FORMATS: FixtureFormat[] = ['cfn', 'cdk', 'terraform'];

function parseArgs(argv: string[]): ParsedArgs {
    let ruleId: string | undefined;
    let fixtureFormat: FixtureFormat | undefined;
    let skipAssessment = false;

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
            case '--skip-assessment':
                skipAssessment = true;
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

    return { ruleId, fixtureFormat, skipAssessment };
}

function printUsage(): void {
    console.log(`Usage:
  bun src/index.ts --rule <checkId> --type <format> [--skip-assessment]

Options:
  --rule <checkId>      Rule ID to refine (e.g. DOCDB-003)
  --type <format>       Fixture format: ${VALID_FIXTURE_FORMATS.join(', ')}
  --skip-assessment     Skip rule assessment phase and go straight to fix validation
  -h, --help            Show this help message
`);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
