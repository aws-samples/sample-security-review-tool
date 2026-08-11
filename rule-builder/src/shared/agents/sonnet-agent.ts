import { Agent, AgentConfig, BedrockModel } from "@strands-agents/sdk";
import { TransientErrorRetryStrategy } from "./transient-error-retry-strategy.js";

export class SonnetAgent extends Agent {
    constructor(config?: AgentConfig | undefined) {
        config = config ?? {};
        config.model = new BedrockModel({ modelId: 'global.anthropic.claude-sonnet-5', maxTokens: 64000 });
        config.retryStrategy = new TransientErrorRetryStrategy();
        super(config);
    }
}