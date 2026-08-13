import { Agent, AgentConfig, BedrockModel } from "@strands-agents/sdk";
import { TransientErrorRetryStrategy } from "./transient-error-retry-strategy.js";
import { DEFAULT_EFFORT, effortRequestFields, type ModelEffort } from "./model-effort.js";
import { bedrockRequestHandler } from "./bedrock-request-handler.js";

export class SonnetAgent extends Agent {
    constructor(config?: AgentConfig | undefined, effort: ModelEffort = DEFAULT_EFFORT) {
        config = config ?? {};
        config.model = new BedrockModel({
            modelId: 'global.anthropic.claude-sonnet-5',
            maxTokens: 64000,
            additionalRequestFields: effortRequestFields(effort),
            clientConfig: { requestHandler: bedrockRequestHandler() },
        });
        config.retryStrategy = new TransientErrorRetryStrategy();
        config.printer = false;
        super(config);
    }
}
