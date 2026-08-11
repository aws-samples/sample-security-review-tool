import { DefaultModelRetryStrategy } from '@strands-agents/sdk';

const MAX_ATTEMPTS = 3;

// Bedrock sometimes closes a stream without a terminal message event. The SDK reports that as a bare
// ModelError carrying this exact text, so matching the message is the only way to single it out.
const DROPPED_STREAM_MESSAGE = 'Stream ended without completing a message';

// Thrown as raw Bedrock exceptions rather than wrapped, so they are identified by name the same way
// the SDK identifies its own. validationException is deliberately absent — a rejected request stays rejected.
const TRANSIENT_BEDROCK_ERRORS = ['InternalServerException', 'ModelStreamErrorException', 'ServiceUnavailableException'];

export class TransientErrorRetryStrategy extends DefaultModelRetryStrategy {
    constructor() {
        super({ maxAttempts: MAX_ATTEMPTS });
    }

    protected override isRetryable(error: Error): boolean {
        if (super.isRetryable(error)) return true;
        return error.message === DROPPED_STREAM_MESSAGE || TRANSIENT_BEDROCK_ERRORS.includes(error.name);
    }
}
