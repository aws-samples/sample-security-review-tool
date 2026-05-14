import { Agent, BedrockModel } from '@strands-agents/sdk';
import { fileEditor } from '@strands-agents/sdk/vended-tools/file-editor';
import { SYSTEM_PROMPT, buildScaffolderPrompt } from './prompt.js';
import type { RequirementsSpec } from '../../shared/types/requirements.js';

export class ScaffolderAgent {
    public async invoke(ruleId: string, service: string, description: string, spec: RequirementsSpec, controlPath: string, adaptersDir: string, adaptersExist: boolean): Promise<void> {
        const userPrompt = buildScaffolderPrompt(ruleId, service, description, spec, controlPath, adaptersDir, adaptersExist);

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-sonnet-4-7', maxTokens: 32768 }),
            tools: [fileEditor],
            systemPrompt: SYSTEM_PROMPT,
        });

        await agent.invoke(userPrompt);
    }
}
