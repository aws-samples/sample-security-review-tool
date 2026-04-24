import { Agent, BedrockModel, McpClient } from '@strands-agents/sdk';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import type { RuleEntry } from '../../shared/rule-catalog/src/index.js';
import type { ReviewerSession, RuleImplVerdict } from './types.js';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompts.js';
import { createSubmitVerdictTool } from './submit-verdict-tool.js';

/**
 * Reviews one security-matrix rule's detection logic against AWS documentation.
 *
 * Tools are a mix of:
 *   - Remote AWS Knowledge MCP Server (no auth, public endpoint).
 *   - A single local submit_impl_verdict tool that receives the structured
 *     verdict and ends the agent loop.
 */
export class RuleImplReviewer {
    constructor(private readonly mcpClient: McpClient) {}

    public async review(rule: RuleEntry): Promise<RuleImplVerdict> {
        const session: ReviewerSession = { verdict: null };
        const agent = this.createAgent(session, rule);

        try {
            await agent.invoke(buildUserPrompt(rule));
        } catch (error) {
            SrtLogger.logError('RuleImplReviewer invocation failed', error as Error, { checkId: rule.checkId });
            if (session.verdict) return session.verdict;
            return this.errorVerdict(rule, (error as Error).message);
        }

        if (session.verdict) return session.verdict;
        return this.errorVerdict(rule, 'agent finished without calling submit_impl_verdict');
    }

    private createAgent(session: ReviewerSession, rule: RuleEntry): Agent {
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
                this.mcpClient,
                createSubmitVerdictTool(session, rule.checkId, rule.description, rule.sourceHash),
            ],
            printer: false,
        });
    }

    private errorVerdict(rule: RuleEntry, reason: string): RuleImplVerdict {
        return {
            checkId: rule.checkId,
            ruleDescription: rule.description,
            correctness: 'INCORRECT',
            correctnessReasoning: `reviewer-error: ${reason}`,
            awsDocCitations: [],
            missedCases: [],
            falsePositiveRisks: [],
            knownLimitations: [],
            suggestedLogicChanges: '',
            ruleSourceHash: rule.sourceHash,
        };
    }
}
