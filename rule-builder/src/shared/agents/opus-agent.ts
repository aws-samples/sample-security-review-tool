import { Agent, AgentConfig, BedrockModel } from "@strands-agents/sdk";

export class OpusAgent extends Agent {
    constructor(config?: AgentConfig | undefined) {
        config = config ?? {};
        config.model = new BedrockModel({ modelId: 'global.anthropic.claude-opus-5' });
        super(config);
    }
}