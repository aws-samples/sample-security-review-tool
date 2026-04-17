import { Message, Tool } from '@aws-sdk/client-bedrock-runtime';
import { FixChange } from '../types.js';

export interface ToolInvocation {
    toolUseId: string;
    name: string;
    input: Record<string, unknown>;
}

export interface ToolOutput {
    json?: unknown;
    text?: string;
    isError?: boolean;
}

export interface AgentTool {
    definition: Tool;
    invoke(input: Record<string, unknown>): Promise<ToolOutput>;
}

export interface AgentResult {
    finalMessage: Message;
    edits: FixChange[];
    comments: string;
    turns: number;
    stopReason: 'finished' | 'end_turn' | 'max_turns' | 'error';
}
