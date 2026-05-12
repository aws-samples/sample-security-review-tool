import * as path from 'path';
import type { FixtureFormat } from './shared/rule-catalog/index.js';
import type { RuleFixtureAgent } from './agents/rule-fixture/agent.js';
import type { FixInstructionValidationAgent } from './agents/fix-instruction-validation/agent.js';
import type { FixInstructionUpdaterAgent } from './agents/fix-instruction-updater/agent.js';
import { writeFixtureFiles } from './agents/rule-fixture/fixture-writer.js';
import { RuleCatalog } from './shared/rule-catalog/index.js';
import { extractVariants } from './shared/variant-extractor.js';
import { fixtureDirFor, srtRepoRoot } from './shared/fixture-paths.js';

const MAX_RETRIES = 5;

export class FixInstructionRefinementCoordinator {
    constructor(
        private fixtureAgent: RuleFixtureAgent,
        private validationAgent: FixInstructionValidationAgent,
        private updaterAgent: FixInstructionUpdaterAgent,
    ) {}

    public async run(ruleId: string, fixtureFormat: FixtureFormat): Promise<void> {
        const fixturesRoot = path.join(srtRepoRoot(), 'evaluators', 'rule-refiner', 'fixtures');

        console.log(`Generating test fixtures for rule ${ruleId}...`);
        const fixtureOutput = await this.fixtureAgent.invoke(ruleId, fixtureFormat);

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

        for (const variant of effectiveVariants) {
            const formatVariants = fixtureFormat === 'cfn' || fixtureFormat === 'cdk'
                ? ['cfn', 'cdk'] as const
                : [fixtureFormat] as const;

            for (const formatVariant of formatVariants) {
                await this.validateVariant(ruleId, fixtureFormat, rule.checkId, variant, formatVariant, fixturesRoot);
            }
        }
    }

    private async validateVariant(ruleId: string, fixtureFormat: FixtureFormat, checkId: string, variant: { variantId: string; fixGuidance: string; label: string }, formatVariant: string, fixturesRoot: string): Promise<void> {
        console.log(`  Validating fix instructions: ${variant.variantId}/${formatVariant}`);

        let previousNewIssues: string | null = null;

        for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
            const fixtureDir = fixtureDirFor(fixturesRoot, 'security-matrix', formatVariant, checkId, variant.variantId);

            const result = await this.validationAgent.invoke({
                fixtureDir,
                checkId,
                variantId: variant.variantId,
                formatVariant,
                fixGuidanceOverride: variant.fixGuidance,
            });

            if (!result.scanFoundIssue) {
                console.warn(`    Fixture did not trigger rule — skipping`);
                return;
            }

            if (result.fixResolved && result.newIssuesIntroduced.length === 0) {
                console.log(`    PASSED (attempt ${attempt + 1})`);
                return;
            }

            const currentNewIssues = result.newIssuesIntroduced.sort().join(',');
            if (currentNewIssues === previousNewIssues) {
                console.warn(`    FAILED: repeated identical issues — fixture likely incompatible with fix instructions: ${result.failureDetails}`);
                return;
            }
            previousNewIssues = currentNewIssues;

            if (attempt === MAX_RETRIES - 1) {
                console.warn(`    FAILED after ${MAX_RETRIES} attempts: ${result.failureDetails}`);
                return;
            }

            console.log(`    Attempt ${attempt + 1} failed: ${result.failureDetails}. Updating fix instructions...`);
            await this.updaterAgent.invoke(ruleId, fixtureFormat, variant, result, fixtureDir);
            await RuleCatalog.refresh();

            const refreshedRule = await RuleCatalog.find(ruleId, fixtureFormat);
            const refreshedVariants = extractVariants(refreshedRule.ruleBody);
            const refreshedVariant = refreshedVariants.find(v => v.variantId === variant.variantId);
            variant.fixGuidance = refreshedVariant?.fixGuidance ?? refreshedRule.fixGuidance;
        }
    }
}
