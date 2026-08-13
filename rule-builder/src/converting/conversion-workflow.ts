import { RuleContext } from '../shared/rule-context.js';
import { BuildWorkflow, type BuildOptions } from '../building/build-workflow.js';
import { LegacyRuleReader, type LegacyRule } from './legacy-rule-reader.js';
import { LegacyRuleRemover } from './legacy-rule-remover.js';
import { DescriptionRewriter } from './description-rewriter.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

export class ConversionWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly legacyRuleId: string) { }

    public async run(options: BuildOptions = {}): Promise<void> {
        const legacy = await new LegacyRuleReader(this.legacyRuleId).read();
        const ruleId = this.controlRuleId(legacy.ruleId);

        this.logger.runStart(ruleId, `converting ${legacy.ruleId} · ${legacy.description}`);
        const description = await this.rewriteDescription(legacy);

        await new BuildWorkflow(new RuleContext(ruleId, legacy.service, description)).run({
            ...options,
            afterImplementation: () => this.removeLegacyRule(legacy),
        });
        this.logger.runComplete(ruleId);
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
