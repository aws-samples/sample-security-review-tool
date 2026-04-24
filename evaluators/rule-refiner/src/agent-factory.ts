import { Agent, BedrockModel, SummarizingConversationManager } from '@strands-agents/sdk';
import type { McpClient } from '@strands-agents/sdk';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';
import type { RefinerSession } from './types.js';
import { SYSTEM_PROMPT } from './prompts.js';
import { createReadFileTool } from './tools/read-file.js';
import { createWriteFileTool } from './tools/write-file.js';
import { createWriteFixtureFilesTool } from './tools/write-fixture-files.js';
import { createScanFixtureTool } from './tools/scan-fixture.js';
import { createRunFixTool } from './tools/run-fix.js';
import { createRescanFixtureTool } from './tools/rescan-fixture.js';
import { createResetFixtureTool } from './tools/reset-fixture.js';
import { createSubmitResultTool } from './tools/submit-result.js';
import { IterationLimitPlugin } from './plugins/iteration-limit-plugin.js';

export function createRefinerAgent(session: RefinerSession, mcpClient: McpClient): Agent {
    const profile = BedrockConfig.getProfile();
    const region = BedrockConfig.getRegion();
    const model = new BedrockModel({
        modelId: BedrockConfig.getModelIdWithInferenceProfilePrefix(),
        clientConfig: {
            region,
            credentials: fromNodeProviderChain(profile !== 'default' ? { profile } : {}),
            requestHandler: new FetchHttpHandler(),
        },
    });

    return new Agent({
        model,
        systemPrompt: SYSTEM_PROMPT,
        tools: [
            mcpClient,
            createReadFileTool(session),
            createWriteFileTool(session),
            createWriteFixtureFilesTool(session),
            createScanFixtureTool(session),
            createRunFixTool(session),
            createRescanFixtureTool(session),
            createResetFixtureTool(session),
            createSubmitResultTool(session),
        ],
        conversationManager: new SummarizingConversationManager({
            summaryRatio: 0.3,
            preserveRecentMessages: 10,
        }),
        plugins: [new IterationLimitPlugin()],
        printer: false,
    });
}
