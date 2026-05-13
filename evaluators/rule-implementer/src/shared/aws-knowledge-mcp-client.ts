import { McpClient } from '@strands-agents/sdk';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

const AWS_KNOWLEDGE_MCP_URL = 'https://knowledge-mcp.global.api.aws';

export function createAwsKnowledgeMcpClient(): McpClient {
    return new McpClient({
        transport: new StreamableHTTPClientTransport(new URL(AWS_KNOWLEDGE_MCP_URL)) as Transport,
    });
}
