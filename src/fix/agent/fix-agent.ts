import { Agent, BedrockModel } from '@strands-agents/sdk';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';
import { ScanResult } from '../../assess/scanning/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { BedrockConfig } from '../../config/aws/bedrock-config.js';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { Fix } from '../types.js';
import { getSystemPrompt } from './prompts/system-prompt.js';
import { buildUserPrompt } from './prompts/user-prompt-builder.js';
import { ContextLoader } from './prompts/context-loader.js';
import { EditSession } from './staging/edit-session.js';
import { WorkspaceGuard } from './staging/workspace-guard.js';
import { createApplyFixTool } from './tools/apply-fix-tool.js';
import { createGiveUpTool } from './tools/give-up-tool.js';
import { AgentLogger } from './logging/agent-logger.js';
import { bridgeStrandsLoggingToSrt } from './logging/strands-log-bridge.js';
import { LoggingPlugin } from './plugins/logging-plugin.js';
import { ApplyFixLimitPlugin } from './plugins/tool-call-limit-plugin.js';
import { AgentSession, StrandsAgentResult, StrandsStopReason } from './types.js';

const MAX_APPLY_FIX_CALLS = 5;

/**
 * Fix agent built on @strands-agents/sdk. Given a single ScanResult, loads the
 * relevant source into the prompt, runs a two-tool agent loop (apply_fix,
 * give_up), and returns the staged edits as a Fix.
 */
export class StrandsFixAgent {
    private readonly logger = new AgentLogger();

    constructor(private readonly context: ProjectContext) {
        bridgeStrandsLoggingToSrt();
    }

    public async run(issue: ScanResult): Promise<StrandsAgentResult> {
        const loadedContext = await new ContextLoader(this.context).load(issue);
        const guard = new WorkspaceGuard(this.context.getProjectRootFolderPath());
        const systemPrompt = getSystemPrompt(issue.source);
        const session: AgentSession = {
            editSession: new EditSession(guard),
            loadedContext,
            projectRootFolderPath: this.context.getProjectRootFolderPath(),
            comments: '',
            gaveUp: null,
            finished: false,
            lastValidation: null,
        };

        const userPrompt = buildUserPrompt(issue, this.context.getProjectRootFolderPath(), loadedContext);
        this.logger.sessionStarted(issue, systemPrompt.length, userPrompt);

        const agent = this.createAgent(session, systemPrompt);
        const stopReason = await this.invokeAgent(agent, userPrompt, session, issue);

        const result: StrandsAgentResult = {
            edits: session.editSession.getChanges(),
            comments: session.comments,
            stopReason,
            gaveUpReason: session.gaveUp?.reason,
            validation: session.lastValidation,
        };
        this.logger.sessionEnded(stopReason, result.edits.length, result.comments);
        return result;
    }

    public toFix(result: StrandsAgentResult): Fix | null {
        if (result.edits.length === 0) return null;
        return { changes: result.edits, comments: result.comments };
    }

    private createAgent(session: AgentSession, systemPrompt: string): Agent {
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
            systemPrompt,
            tools: [
                createApplyFixTool(session, this.context),
                createGiveUpTool(session),
            ],
            plugins: [
                new LoggingPlugin(this.logger),
                new ApplyFixLimitPlugin(MAX_APPLY_FIX_CALLS),
            ],
            printer: false,
        });
    }

    private async invokeAgent(
        agent: Agent,
        userPrompt: string,
        session: AgentSession,
        issue: ScanResult,
    ): Promise<StrandsStopReason> {
        try {
            const result = await agent.invoke(userPrompt);
            if (session.finished) return 'finished';
            if (session.gaveUp) return 'gave_up';
            if (result.stopReason === 'end_turn') return 'end_turn';
            if (result.stopReason === 'max_tokens') return 'max_turns';
            return 'error';
        } catch (error) {
            SrtLogger.logError(
                'StrandsFixAgent invocation failed',
                error as Error,
                { checkId: issue.check_id, path: issue.path },
            );
            return 'error';
        }
    }
}
