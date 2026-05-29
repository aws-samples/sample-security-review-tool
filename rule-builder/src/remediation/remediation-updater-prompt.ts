import { RuleContext } from '../shared/rule-context.js';
import { FixValidationResult } from './fixture-remediator.js';

export class RemediationUpdaterPromptBuilder {
    public buildSystemPrompt(): string {
        return `You rewrite security rule remediation instructions so that the fix agent produces correct fixes. 
        - The remediation instructions must address the issues described in the failure details.
        - The remediation instructions must be format-agnostic (no CloudFormation property names, no Terraform argument names).`;
    }

    public buildUserPrompt(failureDetails: FixValidationResult, fixtureContent: string): string {
        return `${failureDetails.failureDescription} Update the remediation instructions to fix the problem.
        
        <failing-remediation-instructions>
        ${failureDetails.targetIssue.fix}
        </failing-remediation-instructions>

        ${failureDetails.introducedRegressions ? `<new-issues>${failureDetails.introducedFindings.map(x => `<issue>\n<id>${x.check_id}</id>\n<description>${x.issue}</description>\n<remediation-instructions>${x.fix}</remediation-instructions>\n</issue>`)}</new-issues>` : ''}

        <fixture-content-produced-by-failing-remediation-instructions>
        ${fixtureContent}
        </fixture-content-produced-by-failing-remediation-instructions>`;
    }   
}
