import z from 'zod';
import { SonnetAgent } from '../shared/agents/sonnet-agent.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';

const RewrittenDescriptionSchema = z.object({
    description: z.string().describe('The requirement stated as intent, in one sentence'),
});

export class DescriptionRewriter {
    public async rewrite(description: string): Promise<string> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new SonnetAgent({
                tools: [mcpClient],
                systemPrompt: SYSTEM_PROMPT,
                structuredOutputSchema: RewrittenDescriptionSchema,
            });

            const result = await agent.invoke(this.buildUserPrompt(description));
            return (result.structuredOutput as z.infer<typeof RewrittenDescriptionSchema>).description;
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }

    private buildUserPrompt(description: string): string {
        return `## Current description\n\n${description}\n\nRestate the description as the requirement it enforces.`;
    }
}

const SYSTEM_PROMPT = `You restate a security rule's description.

Existing descriptions name the defect the rule reports, for example "X-Ray tracing not enabled". The replacement states the requirement the rule enforces, for example "Lambda functions must have X-Ray tracing enabled". Everything downstream — the requirements specification, the implementation, the tests — is generated from your sentence and nothing else. So it has to say what configuration is required, precisely enough that someone could decide whether a given resource meets it.

Write one sentence:
- Subject is the resource kind the description names, plural: "Lambda functions", "S3 buckets", "API Gateway methods".
- Verb is "must" or "must not".
- State the required configuration, not the finding, and not how to reach it.
- Keep the scope of the setting the description names. Do not broaden one setting into a general principle.
- Where more than one configuration satisfies the requirement, say so rather than naming only one.

Do not include:
- The rule id, its priority, or remediation steps.
- CloudFormation or Terraform type names, property names, or intrinsic functions. Say "X-Ray tracing", not "TracingConfig.Mode"; say "tracing must be enabled", not "tracing_config must be set".
- Hedging ("should generally", "where appropriate", "may").

The description is your only input and is often vague or imprecise. You have AWS documentation search available — use it to check the setting the description names: what values it takes, what the default is, and what AWS states as the secure configuration. State the requirement the documentation supports, not a stricter one. Where the description and the documentation disagree, follow the documentation.

Examples:
- "X-Ray tracing not enabled" → "Lambda functions must have X-Ray tracing enabled"
- "S3 bucket does not have access logging configured" → "S3 buckets must have server access logging enabled"`;
