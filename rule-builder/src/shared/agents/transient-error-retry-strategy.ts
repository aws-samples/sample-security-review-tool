import {
    AfterModelCallEvent,
    BeforeModelCallEvent,
    ContentBlockEvent,
    DefaultModelRetryStrategy,
    ModelStreamUpdateEvent,
    type LocalAgent,
    type RetryDecision,
} from '@strands-agents/sdk';
import { errorCauseChain } from '../../../../src/shared/error-handling/error-diagnostics.js';
import { SrtLogger } from '../../../../src/shared/logging/srt-logger.js';

const MAX_ATTEMPTS = 3;

// Bedrock sometimes closes a stream without a terminal message event. The SDK reports that as a bare
// ModelError carrying this exact text, so matching the message is the only way to single it out.
const DROPPED_STREAM_MESSAGE = 'Stream ended without completing a message';

// Strands wraps Bedrock service exceptions in ModelError, so classification must inspect every cause.
// Validation and access errors are deliberately absent because an unchanged request will remain rejected.
const TRANSIENT_BEDROCK_ERRORS = new Set([
    'InternalServerException',
    'ModelErrorException',
    'ModelNotReadyException',
    'ModelStreamErrorException',
    'ModelTimeoutException',
    'ServiceUnavailableException',
    'ThrottlingException',
]);

interface StreamedToolCall {
    name: string;
    toolUseId: string;
    inputCharacters: number;
}

export class TransientErrorRetryStrategy extends DefaultModelRetryStrategy {
    private streamedToolCall?: StreamedToolCall;

    constructor() {
        super({ maxAttempts: MAX_ATTEMPTS });
    }

    public override initAgent(agent: LocalAgent): void {
        super.initAgent(agent);
        agent.addHook(BeforeModelCallEvent, () => {
            this.streamedToolCall = undefined;
        });
        agent.addHook(ModelStreamUpdateEvent, event => {
            this.observeStreamEvent(event);
        });
        agent.addHook(ContentBlockEvent, event => {
            if (event.contentBlock.type === 'toolUseBlock' && event.contentBlock.toolUseId === this.streamedToolCall?.toolUseId) {
                this.streamedToolCall = undefined;
            }
        });
        agent.addHook(AfterModelCallEvent, event => {
            if (!event.error && event.attemptCount > 1) this.logModelRecovery(event);
        });
    }

    protected override computeRetryDecision(event: AfterModelCallEvent): RetryDecision {
        const decision = super.computeRetryDecision(event);
        if (event.error) this.logModelFailure(event, decision);
        return decision;
    }

    protected override isRetryable(error: Error): boolean {
        return errorCauseChain(error).some(candidate => {
            if (!(candidate instanceof Error)) return false;
            if (super.isRetryable(candidate)) return true;
            return candidate.message === DROPPED_STREAM_MESSAGE || TRANSIENT_BEDROCK_ERRORS.has(candidate.name);
        });
    }

    private observeStreamEvent(event: ModelStreamUpdateEvent): void {
        const streamEvent = event.event;
        if (streamEvent.type === 'modelContentBlockStartEvent' && streamEvent.start?.type === 'toolUseStart') {
            this.streamedToolCall = {
                name: streamEvent.start.name,
                toolUseId: streamEvent.start.toolUseId,
                inputCharacters: 0,
            };
            return;
        }

        if (streamEvent.type === 'modelContentBlockDeltaEvent' && streamEvent.delta.type === 'toolUseInputDelta' && this.streamedToolCall) {
            this.streamedToolCall.inputCharacters += streamEvent.delta.input.length;
        }
    }

    private logModelFailure(event: AfterModelCallEvent, decision: RetryDecision): void {
        const toolCall = this.streamedToolCall;
        SrtLogger.logError(
            decision.retry ? 'Rule builder model call failed; retrying' : 'Rule builder model call failed; not retrying',
            event.error,
            {
                agentId: event.agent.id,
                modelId: event.model.modelId,
                attemptCount: event.attemptCount,
                maxAttempts: MAX_ATTEMPTS,
                retry: decision.retry,
                retryDelayMs: decision.retry ? decision.waitMs : undefined,
                toolName: toolCall?.name,
                toolUseId: toolCall?.toolUseId,
                toolInputCharacters: toolCall?.inputCharacters,
                availableTools: event.agent.toolRegistry.list().map(tool => tool.name),
            },
        );
    }

    private logModelRecovery(event: AfterModelCallEvent): void {
        SrtLogger.logInfo('Rule builder model call recovered after retry', {
            agentId: event.agent.id,
            modelId: event.model.modelId,
            attemptCount: event.attemptCount,
            availableTools: event.agent.toolRegistry.list().map(tool => tool.name),
        });
    }
}
