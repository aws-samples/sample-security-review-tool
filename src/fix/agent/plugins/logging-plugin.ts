import { AfterToolCallEvent, BeforeToolCallEvent, JsonBlock, LocalAgent, Plugin, ToolResultContent } from '@strands-agents/sdk';
import { AgentLogger } from '../logging/agent-logger.js';

/**
 * Bundles BeforeToolCallEvent / AfterToolCallEvent hooks that forward
 * tool-use activity to SrtLogger via AgentLogger.
 */
export class LoggingPlugin implements Plugin {
    readonly name = 'srt:logging';

    private readonly toolStarts = new Map<string, number>();

    constructor(private readonly logger: AgentLogger) {}

    initAgent(agent: LocalAgent): void {
        agent.addHook(BeforeToolCallEvent, (event) => {
            this.toolStarts.set(event.toolUse.toolUseId, Date.now());
            this.logger.toolInvoked(event.toolUse.name, event.toolUse.input);
        });
        agent.addHook(AfterToolCallEvent, (event) => {
            const startedAt = this.toolStarts.get(event.toolUse.toolUseId) ?? Date.now();
            this.toolStarts.delete(event.toolUse.toolUseId);
            const isError = Boolean(event.error) || event.result.status === 'error';
            this.logger.toolCompleted(
                event.toolUse.name,
                extractJsonPayload(event.result.content),
                isError,
                Date.now() - startedAt,
            );
        });
    }
}

function extractJsonPayload(content: ToolResultContent[]): unknown {
    for (const block of content) {
        if (block instanceof JsonBlock) return block.json;
    }
    return content;
}
