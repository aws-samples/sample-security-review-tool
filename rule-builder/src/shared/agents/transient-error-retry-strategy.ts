import { DefaultModelRetryStrategy } from '@strands-agents/sdk';
import { errorCauseChain } from '../../../../src/shared/error-handling/error-diagnostics.js';

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

export class TransientErrorRetryStrategy extends DefaultModelRetryStrategy {
    constructor() {
        super({ maxAttempts: MAX_ATTEMPTS });
    }

    protected override isRetryable(error: Error): boolean {
        return errorCauseChain(error).some(candidate => {
            if (!(candidate instanceof Error)) return false;
            if (super.isRetryable(candidate)) return true;
            return candidate.message === DROPPED_STREAM_MESSAGE || TRANSIENT_BEDROCK_ERRORS.has(candidate.name);
        });
    }
}
