import * as fs from 'node:fs';
import z from 'zod';
import { SonnetAgent } from '../shared/agents/sonnet-agent.js';
import type { LegacyRule } from './legacy-rule-reader.js';

const RewrittenDescriptionSchema = z.object({
    description: z.string().describe('The requirement stated as intent, in one sentence'),
});

export class DescriptionRewriter {
    public async rewrite(legacy: LegacyRule): Promise<string> {
        const agent = new SonnetAgent({
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: RewrittenDescriptionSchema,
        });

        const result = await agent.invoke(this.buildUserPrompt(legacy));
        return (result.structuredOutput as z.infer<typeof RewrittenDescriptionSchema>).description;
    }

    private buildUserPrompt(legacy: LegacyRule): string {
        return `## Current description\n\n${legacy.description}\n\n## Rule source\n\n${this.readSource(legacy)}\n\nRestate the description as the requirement it enforces.`;
    }

    private readSource(legacy: LegacyRule): string {
        return legacy.sourceFilePaths.map(filePath => fs.readFileSync(filePath, 'utf8')).join('\n\n');
    }
}

const SYSTEM_PROMPT = `You restate a security rule's description.

Existing descriptions name the defect the rule reports ("X-Ray tracing not enabled"). The replacement states the requirement the rule enforces ("Lambda functions must have X-Ray tracing enabled"). It is read on its own, with no access to the rule source, and everything downstream — the requirements specification, the implementation, the tests — is generated from it. So it has to say what configuration is required, precisely enough that someone could decide whether a given resource meets it.

Write one sentence:
- Subject is the resource kind the rule assesses, plural: "Lambda functions", "S3 buckets", "API Gateway methods".
- Verb is "must" or "must not".
- State the required configuration, not the finding, and not how to reach it.
- Keep the scope the rule actually has. Do not broaden a rule about one setting into a general principle, and do not narrow it past what the source checks.
- Where the rule accepts several configurations, say so rather than naming only one.

Do not include:
- The rule id, its priority, or remediation steps.
- CloudFormation or Terraform type names, property names, or intrinsic functions. Say "X-Ray tracing", not "TracingConfig.Mode"; say "tracing must be enabled", not "tracing_config must be set".
- Hedging the rule does not implement ("should generally", "where appropriate", "may").

Examples:
- "X-Ray tracing not enabled" → "Lambda functions must have X-Ray tracing enabled"
- "S3 bucket does not have access logging configured" → "S3 buckets must have server access logging enabled"
- "Lambda function may store sensitive data in environment variables" → "Lambda functions must not hold secret values in environment variables, referencing Secrets Manager or Parameter Store instead"

Use the rule source only to work out what state the rule requires — which resources it assesses, what it accepts, and what it rejects. A rule whose description is vaguer than its check ("may store sensitive data") gets the requirement its code enforces, stated plainly.`;
