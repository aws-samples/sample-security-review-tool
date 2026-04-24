import {
    BedrockRuntimeClient,
    ConverseCommand,
    Message,
    Tool,
    ToolUseBlock,
} from '@aws-sdk/client-bedrock-runtime';
import { BedrockConfig } from '../../../../src/config/aws/bedrock-config.js';
import type { FixtureFormat, RuleEntry } from '../../../shared/rule-catalog/src/index.js';
import type { FindingVariant, FixtureFile, RelatedRuleContext, ValidationFailure } from './types.js';
import { SYNTH_SYSTEM_PROMPT, buildSynthUserPrompt } from './prompts.js';

const MAX_TURNS = 3;

/**
 * Bedrock Converse loop that produces a single fixture. Write-only agent: its
 * sole tool is submit_fixture, which returns a list of files.
 */
export class SynthAgent {
    constructor(private readonly bedrockClient: BedrockRuntimeClient) {}

    public async generate(
        rule: RuleEntry,
        format: FixtureFormat,
        previousFailure: ValidationFailure | null,
        relatedRules: RelatedRuleContext[] = [],
        variant?: FindingVariant,
    ): Promise<FixtureFile[]> {
        const messages: Message[] = [{
            role: 'user',
            content: [{ text: buildSynthUserPrompt(rule, format, previousFailure, relatedRules, variant) }],
        }];

        for (let turn = 0; turn < MAX_TURNS; turn++) {
            const response = await this.bedrockClient.send(new ConverseCommand({
                modelId: BedrockConfig.getModelIdWithInferenceProfilePrefix(),
                system: [{ text: SYNTH_SYSTEM_PROMPT }],
                messages,
                toolConfig: { tools: this.toolSchemas() },
            }));

            const assistantMessage = response.output?.message;
            if (!assistantMessage) break;
            messages.push(assistantMessage);

            const toolUse = this.extractSubmit(assistantMessage);
            if (toolUse) {
                return this.parseFixtureFiles(toolUse.input as Record<string, unknown>);
            }

            messages.push({
                role: 'user',
                content: [{ text: 'You must call submit_fixture with the fixture files. Do not narrate.' }],
            });
        }

        throw new Error(`SynthAgent: ${rule.checkId} (${format}) did not call submit_fixture within ${MAX_TURNS} turns`);
    }

    private extractSubmit(message: Message): ToolUseBlock | null {
        for (const block of message.content ?? []) {
            if (block.toolUse?.name === 'submit_fixture') return block.toolUse;
        }
        return null;
    }

    private parseFixtureFiles(input: Record<string, unknown>): FixtureFile[] {
        const raw = Array.isArray(input.files) ? input.files : [];
        const files: FixtureFile[] = [];
        for (const entry of raw) {
            if (!entry || typeof entry !== 'object') continue;
            const record = entry as Record<string, unknown>;
            const relativePath = typeof record.relativePath === 'string' ? record.relativePath : '';
            const content = typeof record.content === 'string' ? record.content : '';
            if (relativePath && content) {
                files.push({ relativePath, content });
            }
        }
        if (files.length === 0) {
            throw new Error('SynthAgent: submit_fixture returned no files');
        }
        return files;
    }

    private toolSchemas(): Tool[] {
        return [
            {
                toolSpec: {
                    name: 'submit_fixture',
                    description: 'Submit the complete set of files for the fixture. Must be called exactly once.',
                    inputSchema: {
                        json: {
                            type: 'object',
                            properties: {
                                files: {
                                    type: 'array',
                                    items: {
                                        type: 'object',
                                        properties: {
                                            relativePath: { type: 'string', description: 'Path relative to the fixture root.' },
                                            content: { type: 'string', description: 'Full file contents.' },
                                        },
                                        required: ['relativePath', 'content'],
                                    },
                                },
                            },
                            required: ['files'],
                        },
                    },
                },
            },
        ];
    }
}
