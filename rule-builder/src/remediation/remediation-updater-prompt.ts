import { FixValidationResult } from './fix-validation-result.js';

export class RemediationUpdaterPromptBuilder {
    public buildSystemPrompt(): string {
        return `You rewrite security rule remediation instructions so that the fix agent produces correct fixes.
        - The remediation instructions must address the issues described in the failure details.
        - Read the embedded control evaluate() method and adapter source to determine the EXACT condition that makes the finding pass, then base the rewritten instructions on that condition rather than guessing.
        - The remediation instructions must be format-agnostic (no CloudFormation property names, no Terraform argument names).
        - Write instructions for this rule only. Requirements of other rules are appended to your instructions automatically, so never restate another rule's requirements.`;
    }

    public buildUserPrompt(failureDetails: FixValidationResult, failingRemediation: string, fixtureContent: string, controlSource: string, adapterSource: string): string {
        return `${failureDetails.failureDescription} Update the remediation instructions to fix the problem.

        <failing-remediation-instructions>
        ${failingRemediation}
        </failing-remediation-instructions>

        <rule-source-defining-pass-fail-criteria>
        ${controlSource}

        ${adapterSource}
        </rule-source-defining-pass-fail-criteria>

        <fixture-content-produced-by-failing-remediation-instructions>
        ${fixtureContent}
        </fixture-content-produced-by-failing-remediation-instructions>`;
    }
}
