import { Agent, AgentConfig, BedrockModel } from "@strands-agents/sdk";
import { TransientErrorRetryStrategy } from "./transient-error-retry-strategy.js";
import { DEFAULT_EFFORT, effortRequestFields, type ModelEffort } from "./model-effort.js";

export class OpusAgent extends Agent {
    constructor(config?: AgentConfig | undefined, effort: ModelEffort = DEFAULT_EFFORT) {
        config = config ?? {};
        config.model = new BedrockModel({
            modelId: 'global.anthropic.claude-opus-5',
            maxTokens: 64000,
            additionalRequestFields: effortRequestFields(effort),
        });
        config.retryStrategy = new TransientErrorRetryStrategy();
        super(config);
    }
}
