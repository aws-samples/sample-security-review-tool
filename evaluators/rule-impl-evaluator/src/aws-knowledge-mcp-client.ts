import { McpClient } from '@strands-agents/sdk';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

const AWS_KNOWLEDGE_MCP_URL = 'https://knowledge-mcp.global.api.aws';

/**
 * Constructs a Strands McpClient pointed at the public AWS Knowledge MCP
 * Server. Purpose-built for AWS-documentation lookups: no auth, no API key,
 * no scraping. Strands' McpClient implements ToolProvider so the returned
 * instance can be passed directly to Agent({ tools: [...] }).
 */
export function createAwsKnowledgeMcpClient(): McpClient {
    return new McpClient({
        transport: new StreamableHTTPClientTransport(new URL(AWS_KNOWLEDGE_MCP_URL)) as Transport,
    });
}
