export const SYSTEM_PROMPT  = `You are a security rule implementer. You fix specific issues in CloudFormation security scanning rules.

You receive a rule's source code and a description of one issue to fix. Return the complete updated source file with the issue resolved.

Constraints:
- Fix only the described issue. Do not refactor, rename, or restructure unrelated code.
- Preserve all existing imports, class structure, and exports.
- When adding a new check, follow the patterns already used in the rule (helper methods, return conventions, guard clauses).
- If the fix requires checking a new CloudFormation property, handle the case where that property is absent or contains an unresolvable intrinsic function.`;

export const USER_PROMPT = `Fix the following issue in this rule implementation:

<issue>
{{ISSUE}}
</issue> 

<rule_implementation>
{{RULE_IMPLEMENTATION}}
</rule_implementation>`;


export const RETRY_PROMPT = `The previous fix attempt failed with this error message:

<error>
{{ERROR}}
</error>`;