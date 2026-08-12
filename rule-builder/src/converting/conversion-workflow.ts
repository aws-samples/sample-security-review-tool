import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import { BuildWorkflow, type BuildOptions } from '../building/build-workflow.js';
import { LegacyRuleReader, type LegacyRule } from './legacy-rule-reader.js';
import { DescriptionRewriter } from './description-rewriter.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const LEGACY_RULE_FILE_SUFFIX_PATTERN = /\.(cf|tf)\.ts$/;

export class ConversionWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly legacyRuleId: string) { }

    public async run(options: BuildOptions = {}): Promise<void> {
        const legacy = await new LegacyRuleReader(this.legacyRuleId).read();
        const ruleId = this.controlRuleId(legacy.ruleId);

        this.logger.runStart(ruleId, `converting ${legacy.ruleId} · ${legacy.description}`);
        const description = await this.rewriteDescription(legacy);

        await new BuildWorkflow(new RuleContext(ruleId, legacy.service, description)).run(options);
        this.logger.runComplete(ruleId);

        this.reportLegacyRuleRemoval(legacy);
    }

    private async rewriteDescription(legacy: LegacyRule): Promise<string> {
        const description = await this.logger.task('restating the description as intent', () => new DescriptionRewriter().rewrite(legacy));
        this.logger.step(description);
        return description;
    }

    // Control ids carry no hyphen in the service prefix: legacy API-GW-002 becomes APIGW-002.
    private controlRuleId(legacyRuleId: string): string {
        const numberSeparator = legacyRuleId.lastIndexOf('-');
        if (numberSeparator < 0) return legacyRuleId;
        return legacyRuleId.slice(0, numberSeparator).replaceAll('-', '') + legacyRuleId.slice(numberSeparator);
    }

    private reportLegacyRuleRemoval(legacy: LegacyRule): void {
        this.logger.group(`${legacy.ruleId} left in place`);
        for (const filePath of this.legacyFilePaths(legacy)) this.logger.step(path.relative(RuleContext.srtRootFolderPath(), filePath));
        this.logger.info('Remove these files, and the registrations in index.ts, once the new findings have been compared against the old ones.');
    }

    private legacyFilePaths(legacy: LegacyRule): string[] {
        return [
            ...legacy.sourceFilePaths,
            path.join(RuleContext.rulesRootFolderPath(), legacy.service, 'index.ts'),
            ...this.legacyTestFilePaths(legacy),
        ].filter(filePath => fs.existsSync(filePath));
    }

    private legacyTestFilePaths(legacy: LegacyRule): string[] {
        const testFolderPath = path.join(RuleContext.srtRootFolderPath(), 'tests', 'core', 'scanners', 'srt', 'rules', legacy.service);
        const testFileNames = legacy.sourceFilePaths.map(filePath => `${path.basename(filePath).replace(LEGACY_RULE_FILE_SUFFIX_PATTERN, '')}.test.ts`);
        return [...new Set(testFileNames)].map(fileName => path.join(testFolderPath, fileName));
    }
}
