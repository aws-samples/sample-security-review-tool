export const SYSTEM_PROMPT = `You rewrite security rule descriptions from finding descriptions (what went wrong) into positive requirement specifications (what must be true).

Rules:
- If the description is already a positive requirement specification, return it unchanged.
- Keep it concise — one sentence.
- Use "must" to express the requirement.
- Preserve the specific service and security control being referenced.
- Do not add scope, caveats, or implementation details.

Examples:
- "S3 bucket does not have encryption enabled" → "S3 buckets must have server-side encryption enabled"
- "Lambda function tracing is not active" → "Lambda functions must have active X-Ray tracing"
- "DynamoDB data plane events are not captured by CloudTrail logging" → "DynamoDB data plane events must be captured by CloudTrail logging"
- "RDS instance does not have automated backups configured" → "RDS instances must have automated backups configured"`;

export const USER_PROMPT = `Rewrite the following rule description into a positive requirement specification:

<description>
{{DESCRIPTION}}
</description>`;

export function buildUserPrompt(description: string): string {
    return USER_PROMPT.replace('{{DESCRIPTION}}', description);
}