import { RuleContext } from '../shared/rule-context.js';
import { BuildWorkflow, type BuildOptions } from '../building/build-workflow.js';
import { LegacyRuleReader, LegacyRuleNotFoundError, type LegacyRule } from './legacy-rule-reader.js';
import { LegacyRuleRemover } from './legacy-rule-remover.js';
import { DescriptionRewriter } from './description-rewriter.js';
import { RuleLocator, RuleNotFoundError } from '../shared/rule-locator.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';
import { ConversionCheckpointStore } from './conversion-checkpoint-store.js';

export class ConversionWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly legacyRuleId: string) { }

    public async run(options: BuildOptions = {}): Promise<void> {
        const legacy = await this.findLegacyRule();
        if (!legacy) return this.resume(options);

        const ruleId = this.controlRuleId(legacy.ruleId);
        const converted = this.findConvertedRule(ruleId);
        if (converted) return this.resumeWithLegacy(converted, legacy, options);

        this.logger.runStart(ruleId, `converting ${legacy.ruleId} · ${legacy.description}`);
        const checkpoint = new ConversionCheckpointStore(ruleId, legacy.service);
        const description = await this.description(legacy.description, checkpoint);
        const context = new RuleContext(ruleId, legacy.service, description);

        await this.continueBuild(context, options, legacy);
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

    private async resume(options: BuildOptions): Promise<void> {
        const ruleId = this.controlRuleId(this.legacyRuleId);
        const context = this.findConvertedRule(ruleId);
        if (!context) this.failNeitherFound(ruleId);

        this.logger.runStart(ruleId, `resuming the conversion of ${this.legacyRuleId} · ${context.description}`);
        await this.continueBuild(context, options);
        this.logger.runComplete(ruleId);
    }

    private async resumeWithLegacy(context: RuleContext, legacy: LegacyRule, options: BuildOptions): Promise<void> {
        this.logger.runStart(context.ruleId, `resuming the conversion of ${legacy.ruleId} · ${context.description}`);
        await this.continueBuild(context, options, legacy);
        this.logger.runComplete(context.ruleId);
    }

    private findConvertedRule(ruleId: string): RuleContext | null {
        try {
            return new RuleLocator(ruleId).locate();
        } catch (error) {
            if (error instanceof RuleNotFoundError) return null;
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

    private async description(sourceDescription: string, checkpoint: ConversionCheckpointStore): Promise<string> {
        const saved = checkpoint.read(sourceDescription);
        if (saved !== null) {
            this.logger.step(`using saved description: ${saved}`);
            return saved;
        }

        const updatedDescription = await this.logger.task('restating the description as intent', () => new DescriptionRewriter().rewrite(sourceDescription));
        checkpoint.write(sourceDescription, updatedDescription);
        this.logger.step(updatedDescription);
        return updatedDescription;
    }

    private async continueBuild(context: RuleContext, options: BuildOptions, legacy?: LegacyRule): Promise<void> {
        await new BuildWorkflow(context).run({
            ...options,
            ...(legacy && { afterImplementation: () => this.removeLegacyRule(legacy) }),
        });
        new ConversionCheckpointStore(context.ruleId, context.service).remove();
    }

    // Control ids carry no hyphen in the service prefix: legacy API-GW-002 becomes APIGW-002.
    private controlRuleId(legacyRuleId: string): string {
        const numberSeparator = legacyRuleId.lastIndexOf('-');
        if (numberSeparator < 0) return legacyRuleId;
        return legacyRuleId.slice(0, numberSeparator).replaceAll('-', '') + legacyRuleId.slice(numberSeparator);
    }
}
