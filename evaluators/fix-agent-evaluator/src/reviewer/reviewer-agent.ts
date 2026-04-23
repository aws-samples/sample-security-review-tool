import {
    BedrockRuntimeClient,
    ConverseCommand,
    Message,
    Tool,
    ToolUseBlock,
} from '@aws-sdk/client-bedrock-runtime';
import { BedrockConfig } from '../../../../src/config/aws/bedrock-config.js';
import type { FixRunRecord, RescanResult, ReviewVerdict } from '../types.js';
import { REVIEWER_SYSTEM_PROMPT, buildReviewerUserPrompt } from './prompts.js';
import { ReviewerTools } from './tools.js';

const MAX_TURNS = 12;

/**
 * Bedrock Converse loop that reviews a single FixAgent run and submits a
 * structured verdict via the `submit_verdict` tool. Uses only read-only
 * inspection tools so it cannot alter the target project.
 */
export class ReviewerAgent {
    constructor(
        private readonly bedrockClient: BedrockRuntimeClient,
        private readonly tools: ReviewerTools,
    ) {}

    public async review(
        record: FixRunRecord,
        ruleSourceSnippet: string,
        rescan: RescanResult | null = null,
    ): Promise<ReviewVerdict> {
        const messages: Message[] = [{
            role: 'user',
            content: [{ text: buildReviewerUserPrompt(record, ruleSourceSnippet, rescan) }],
        }];

        let verdict: ReviewVerdict | null = null;

        for (let turn = 0; turn < MAX_TURNS; turn++) {
            const response = await this.bedrockClient.send(new ConverseCommand({
                modelId: BedrockConfig.getModelIdWithInferenceProfilePrefix(),
                system: [{ text: REVIEWER_SYSTEM_PROMPT }],
                messages,
                toolConfig: { tools: this.toolSchemas() },
            }));

            const assistantMessage = response.output?.message;
            if (!assistantMessage) break;
            messages.push(assistantMessage);

            const toolUses = this.extractToolUses(assistantMessage);
            if (toolUses.length === 0) break;

            const toolResultBlocks = [];

            for (const toolUse of toolUses) {
                if (toolUse.name === 'submit_verdict') {
                    verdict = this.buildVerdictFromToolInput(record, toolUse.input as Record<string, unknown>, rescan);
                    toolResultBlocks.push({
                        toolResult: {
                            toolUseId: toolUse.toolUseId!,
                            content: [{ text: 'Verdict received.' }],
                            status: 'success' as const,
                        },
                    });
                    continue;
                }
                const result = await this.runTool(toolUse);
                toolResultBlocks.push({
                    toolResult: {
                        toolUseId: toolUse.toolUseId!,
                        content: [{ text: result }],
                        status: 'success' as const,
                    },
                });
            }

            if (verdict) return verdict;

            messages.push({ role: 'user', content: toolResultBlocks });
        }

        return verdict ?? this.defaultVerdict(record, 'reviewer-did-not-submit-verdict', rescan);
    }

    private extractToolUses(message: Message): ToolUseBlock[] {
        return (message.content ?? [])
            .map(block => block.toolUse)
            .filter((tu): tu is ToolUseBlock => Boolean(tu));
    }

    private async runTool(toolUse: ToolUseBlock): Promise<string> {
        const input = (toolUse.input ?? {}) as Record<string, unknown>;
        try {
            if (toolUse.name === 'list_files') {
                const files = await this.tools.listFiles(String(input.pattern ?? '**/*'));
                return files.join('\n');
            }
            if (toolUse.name === 'grep') {
                return await this.tools.grep(String(input.pattern ?? ''), input.pathGlob ? String(input.pathGlob) : undefined);
            }
            if (toolUse.name === 'read_file') {
                return this.tools.readFile(String(input.path ?? ''));
            }
            return `Unknown tool: ${toolUse.name}`;
        } catch (error) {
            return `Tool error: ${(error as Error).message}`;
        }
    }

    private toolSchemas(): Tool[] {
        return [
            {
                toolSpec: {
                    name: 'list_files',
                    description: 'List files in the target project matching a glob pattern.',
                    inputSchema: {
                        json: {
                            type: 'object',
                            properties: { pattern: { type: 'string' } },
                            required: ['pattern'],
                        },
                    },
                },
            },
            {
                toolSpec: {
                    name: 'grep',
                    description: 'Search files in the target project for a regex.',
                    inputSchema: {
                        json: {
                            type: 'object',
                            properties: {
                                pattern: { type: 'string' },
                                pathGlob: { type: 'string' },
                            },
                            required: ['pattern'],
                        },
                    },
                },
            },
            {
                toolSpec: {
                    name: 'read_file',
                    description: 'Read a file in the target project.',
                    inputSchema: {
                        json: {
                            type: 'object',
                            properties: { path: { type: 'string' } },
                            required: ['path'],
                        },
                    },
                },
            },
            {
                toolSpec: {
                    name: 'submit_verdict',
                    description: 'Submit the final review verdict. Must be called exactly once per review.',
                    inputSchema: {
                        json: {
                            type: 'object',
                            properties: {
                                effectiveness: { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW'] },
                                effectivenessReasoning: { type: 'string' },
                                efficiency: { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW'] },
                                efficiencyReasoning: { type: 'string' },
                                rootCause: { type: 'string' },
                                suggestedFixGuidance: { type: 'string' },
                                additionalRecommendations: { type: 'string' },
                            },
                            required: [
                                'effectiveness',
                                'effectivenessReasoning',
                                'efficiency',
                                'efficiencyReasoning',
                                'rootCause',
                                'suggestedFixGuidance',
                                'additionalRecommendations',
                            ],
                        },
                    },
                },
            },
        ];
    }

    private buildVerdictFromToolInput(
        record: FixRunRecord,
        input: Record<string, unknown>,
        rescan: RescanResult | null,
    ): ReviewVerdict {
        const effectiveness = this.asRating(input.effectiveness);
        const efficiency = this.asRating(input.efficiency);
        const resolvedRescan = rescan ?? emptyRescan();
        return {
            checkId: record.issue.check_id ?? 'unknown',
            source: record.issue.source,
            path: record.issue.path ?? 'unknown',
            resourceName: record.issue.resourceName,
            effectiveness,
            effectivenessReasoning: String(input.effectivenessReasoning ?? ''),
            efficiency,
            efficiencyReasoning: String(input.efficiencyReasoning ?? ''),
            turns: record.session.turns,
            retries: record.session.retries,
            applyFixFailures: record.session.applyFixFailures,
            rootCause: String(input.rootCause ?? 'unknown'),
            currentFixGuidance: record.issue.fix ?? '',
            suggestedFixGuidance: String(input.suggestedFixGuidance ?? ''),
            additionalRecommendations: String(input.additionalRecommendations ?? ''),
            rescan: resolvedRescan,
            overallPass: computeOverallPass(effectiveness, efficiency, resolvedRescan),
            failureReasons: computeFailureReasons(effectiveness, efficiency, resolvedRescan),
        };
    }

    private asRating(value: unknown): 'HIGH' | 'MEDIUM' | 'LOW' {
        const v = String(value ?? '').toUpperCase();
        if (v === 'HIGH' || v === 'MEDIUM' || v === 'LOW') return v;
        return 'LOW';
    }

    private defaultVerdict(record: FixRunRecord, reason: string, rescan: RescanResult | null): ReviewVerdict {
        const resolvedRescan = rescan ?? emptyRescan();
        return {
            checkId: record.issue.check_id ?? 'unknown',
            source: record.issue.source,
            path: record.issue.path ?? 'unknown',
            resourceName: record.issue.resourceName,
            effectiveness: 'LOW',
            effectivenessReasoning: reason,
            efficiency: 'LOW',
            efficiencyReasoning: reason,
            turns: record.session.turns,
            retries: record.session.retries,
            applyFixFailures: record.session.applyFixFailures,
            rootCause: 'reviewer-error',
            currentFixGuidance: record.issue.fix ?? '',
            suggestedFixGuidance: '',
            additionalRecommendations: '',
            rescan: resolvedRescan,
            overallPass: false,
            failureReasons: ['reviewer-error', ...computeFailureReasons('LOW', 'LOW', resolvedRescan)],
        };
    }
}

function emptyRescan(): RescanResult {
    return {
        targetRuleStillFires: false,
        newRulesTriggered: [],
        validationPassed: true,
    };
}

function computeOverallPass(
    effectiveness: 'HIGH' | 'MEDIUM' | 'LOW',
    efficiency: 'HIGH' | 'MEDIUM' | 'LOW',
    rescan: RescanResult,
): boolean {
    return (
        effectiveness === 'HIGH'
        && efficiency === 'HIGH'
        && !rescan.targetRuleStillFires
        && rescan.newRulesTriggered.length === 0
        && rescan.validationPassed
    );
}

function computeFailureReasons(
    effectiveness: 'HIGH' | 'MEDIUM' | 'LOW',
    efficiency: 'HIGH' | 'MEDIUM' | 'LOW',
    rescan: RescanResult,
): string[] {
    const reasons: string[] = [];
    if (effectiveness !== 'HIGH') reasons.push(`effectiveness=${effectiveness}`);
    if (efficiency !== 'HIGH') reasons.push(`efficiency=${efficiency}`);
    if (rescan.targetRuleStillFires) reasons.push('target-rule-still-fires');
    if (rescan.newRulesTriggered.length > 0) reasons.push(`new-rules-triggered:${rescan.newRulesTriggered.join(',')}`);
    if (!rescan.validationPassed) reasons.push('fixture-failed-validation-after-fix');
    return reasons;
}
