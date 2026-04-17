import {
    BedrockRuntimeClient,
    ConverseCommand,
    ContentBlock,
    Message,
    ToolResultContentBlock,
    ToolUseBlock,
} from '@aws-sdk/client-bedrock-runtime';
import { ScanResult } from '../../assess/scanning/types.js';
import { BedrockConfig } from '../../config/aws/bedrock-config.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { Fix } from '../types.js';
import { ToolRegistry } from './tool-registry.js';
import { AgentResult, ToolOutput } from './types.js';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompts.js';

const DEFAULT_MAX_TURNS = 12;

/**
 * Agent loop built on top of the Bedrock Converse API tool-use protocol.
 *
 * Each turn:
 *   1. Send accumulated messages + tool schemas to the model.
 *   2. If the model asks to use tools, invoke them locally and append the
 *      results to the conversation.
 *   3. Stop when the model stops requesting tools or calls finish().
 *
 * The agent stages edits in memory (via the ToolRegistry's EditRecorder) and
 * returns them so the caller can preview + commit them separately.
 */
export class FixAgent {
    private readonly registry: ToolRegistry;

    constructor(private readonly bedrockClient: BedrockRuntimeClient, context: ProjectContext) {
        this.registry = new ToolRegistry(context);
    }

    public async run(issue: ScanResult, maxTurns: number = DEFAULT_MAX_TURNS): Promise<AgentResult> {
        const messages: Message[] = [{ role: 'user', content: [{ text: buildUserPrompt(issue) }] }];

        for (let turn = 0; turn < maxTurns; turn++) {
            const response = await this.bedrockClient.send(new ConverseCommand({
                modelId: BedrockConfig.getModelIdWithInferenceProfilePrefix(),
                system: [{ text: SYSTEM_PROMPT }],
                messages,
                toolConfig: { tools: this.registry.describe() },
                inferenceConfig: { temperature: 0 },
            }));

            const assistantMessage = response.output?.message;
            if (!assistantMessage) {
                return this.buildResult({ role: 'assistant', content: [] }, turn + 1, 'error');
            }

            messages.push(assistantMessage);

            if (this.registry.finishTool.wasCalled()) {
                return this.buildResult(assistantMessage, turn + 1, 'finished');
            }

            if (response.stopReason !== 'tool_use') {
                return this.buildResult(assistantMessage, turn + 1, 'end_turn');
            }

            const toolResultContent = await this.runToolCalls(assistantMessage);
            messages.push({ role: 'user', content: toolResultContent });
        }

        SrtLogger.logError(
            'FixAgent exceeded max turns',
            new Error(`Max turns: ${maxTurns}`),
            { checkId: issue.check_id, path: issue.path },
        );
        return this.buildResult({ role: 'assistant', content: [] }, maxTurns, 'max_turns');
    }

    public toFix(result: AgentResult): Fix | null {
        if (result.edits.length === 0) return null;
        return { changes: result.edits, comments: result.comments };
    }

    private async runToolCalls(assistantMessage: Message): Promise<ContentBlock[]> {
        const toolUses = this.extractToolUses(assistantMessage);
        const results: ContentBlock[] = [];

        for (const toolUse of toolUses) {
            const output = await this.safeInvoke(toolUse);
            results.push({
                toolResult: {
                    toolUseId: toolUse.toolUseId!,
                    content: this.formatOutput(output),
                    status: output.isError ? 'error' : 'success',
                },
            });
        }

        return results;
    }

    private extractToolUses(message: Message): ToolUseBlock[] {
        return (message.content ?? [])
            .map(block => block.toolUse)
            .filter((tu): tu is ToolUseBlock => Boolean(tu));
    }

    private async safeInvoke(toolUse: ToolUseBlock): Promise<ToolOutput> {
        try {
            const input = (toolUse.input ?? {}) as Record<string, unknown>;
            return await this.registry.invoke(toolUse.name!, input);
        } catch (error) {
            return { text: `Tool threw: ${(error as Error).message}`, isError: true };
        }
    }

    private formatOutput(output: ToolOutput): ToolResultContentBlock[] {
        if (output.json !== undefined) return [{ json: output.json as any }];
        return [{ text: output.text ?? '' }];
    }

    private buildResult(finalMessage: Message, turns: number, stopReason: AgentResult['stopReason']): AgentResult {
        return {
            finalMessage,
            edits: this.registry.editRecorder.toFixChanges(),
            comments: this.registry.finishTool.getComments(),
            turns,
            stopReason,
        };
    }
}
