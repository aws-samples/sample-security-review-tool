import { Agent, AgentConfig, BedrockModel } from "@strands-agents/sdk";

export class SonnetAgent extends Agent {
    constructor(config?: AgentConfig | undefined) {
        config = config ?? {};
        config.model = new BedrockModel({ modelId: 'global.anthropic.claude-sonnet-5' });
        super(config);
    }
}