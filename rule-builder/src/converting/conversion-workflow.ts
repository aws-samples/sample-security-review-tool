import { RuleContext } from '../shared/rule-context.js';
import { BuildWorkflow, type BuildOptions } from '../building/build-workflow.js';
import { LegacyRuleReader, LegacyRuleNotFoundError, type LegacyRule } from './legacy-rule-reader.js';
import { LegacyRuleRemover } from './legacy-rule-remover.js';
import { DescriptionRewriter } from './description-rewriter.js';
import { RuleLocator, RuleNotFoundError } from '../shared/rule-locator.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

export class ConversionWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly legacyRuleId: string) { }

    public async run(options: BuildOptions = {}): Promise<void> {
        const legacy = await this.findLegacyRule();
        if (!legacy) return this.resume(options);

        const ruleId = this.controlRuleId(legacy.ruleId);

        this.logger.runStart(ruleId, `converting ${legacy.ruleId} · ${legacy.description}`);
        const description = await this.rewriteDescription(legacy);

        await new BuildWorkflow(new RuleContext(ruleId, legacy.service, description)).run({
            ...options,
            afterImplementation: () => this.removeLegacyRule(legacy),
        });
        this.logger.runComplete(ruleId);
    }

    private async findLegacyRule(): Promise<LegacyRule | null> {
        try {
            return await new LegacyRuleReader(this.legacyRuleId).read();
        } catch (error) {
            if (error instanceof LegacyRuleNotFoundError) return null;
            throw error;
        }
    }

    /**
     * Conversion deletes the legacy rule once the new one is implemented, so a second run
     * has no legacy source to read the service and description from. The already converted
     * rule carries both, which lets a conversion that failed after phase 3 be resumed.
     */
    private async resume(options: BuildOptions): Promise<void> {
        const ruleId = this.controlRuleId(this.legacyRuleId);
        const context = this.locateConvertedRule(ruleId);

        this.logger.runStart(ruleId, `resuming the conversion of ${this.legacyRuleId} · ${context.description}`);
        await new BuildWorkflow(context).run(options);
        this.logger.runComplete(ruleId);
    }

    private locateConvertedRule(ruleId: string): RuleContext {
        try {
            return new RuleLocator(ruleId).locate();
        } catch (error) {
            if (error instanceof RuleNotFoundError) this.failNeitherFound(ruleId);
            throw error;
        }
    }

    private failNeitherFound(ruleId: string): never {
        throw new LegacyRuleNotFoundError(`No legacy rule with id '${this.legacyRuleId}' found under the security-matrix rules directory, and no converted rule '${ruleId}' to resume. Ids are the ones the rule declares itself, e.g. LAMBDA-013 or API-GW-002.`);
    }

    private removeLegacyRule(legacy: LegacyRule): void {
        const removedPaths = new LegacyRuleRemover(legacy).remove();
        this.logger.group(`${legacy.ruleId} removed`);
        for (const filePath of removedPaths) this.logger.step(filePath);
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
}
