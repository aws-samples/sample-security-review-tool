import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';

const REQUEST_TIMEOUT_MS = 120_000;

// Bun's node:http2 registers each stream's timeout callback on the session's shared TLS socket and
// never removes it, so the Bedrock SDK's default http2 handler trips MaxListenersExceededWarning
// after ten calls. Fetch keeps the agents off that path, as the fix agent already does.
export function bedrockRequestHandler(): FetchHttpHandler {
    return new FetchHttpHandler({ requestTimeout: REQUEST_TIMEOUT_MS });
}
