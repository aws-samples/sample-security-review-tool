import type { RuleImplVerdict, ReviewVerdict } from './types.js';

export function buildImplPrompt(ruleId: string, verdict: RuleImplVerdict): string {
    const missedCases = verdict.missedCases.length > 0
        ? verdict.missedCases.map(c => `  - ${c}`).join('\n')
        : '  (none)';

    const falsePositives = verdict.falsePositiveRisks.length > 0
        ? verdict.falsePositiveRisks.map(r => `  - ${r}`).join('\n')
        : '  (none)';

    return `You are refining the detection logic for security-matrix rule ${ruleId}.

The rule-impl-evaluator rated this rule as ${verdict.correctness}. Here is its analysis:

REASONING:
${verdict.correctnessReasoning}

MISSED CASES:
${missedCases}

FALSE-POSITIVE RISKS:
${falsePositives}

SUGGESTED LOGIC CHANGES:
${verdict.suggestedLogicChanges}

Your task:
1. Find the rule source file for ${ruleId} under src/assess/scanning/security-matrix/rules/
   (search for the string '${ruleId}' in the super() constructor call)
2. Implement the suggested logic changes described above
3. Follow the existing code patterns and conventions in the rule file
4. Run the existing unit tests for this rule if they exist under tests/ and fix any failures
5. Do NOT modify any other rules
6. Do NOT commit any changes`;
}

export function buildFixPrompt(ruleId: string, failures: ReviewVerdict[]): string {
    const failureSections = failures.map(v => {
        const lines = [
            `Variant: ${v.variantId ?? 'default'} | Path: ${v.path} | Resource: ${v.resourceName ?? 'N/A'}`,
            `Effectiveness: ${v.effectiveness} — ${v.effectivenessReasoning}`,
            `Failure reasons: ${v.failureReasons.join(', ')}`,
        ];
        if (v.suggestedFixGuidance) {
            lines.push(`Suggested fix guidance:\n${v.suggestedFixGuidance}`);
        }
        if (v.additionalRecommendations) {
            lines.push(`Additional recommendations: ${v.additionalRecommendations}`);
        }
        return lines.join('\n');
    });

    return `You are refining the fix guidance for security-matrix rule ${ruleId}.

The fix-agent-evaluator found that the following fix variants failed:

${failureSections.join('\n\n---\n\n')}

Your task:
1. Find the rule source file for ${ruleId} under src/assess/scanning/security-matrix/rules/
   (search for the string '${ruleId}' in the super() constructor call)
2. Update the fix guidance text in the createResult() or createScanResult() calls to address the failures
3. Incorporate the suggested fix guidance from the evaluator report where provided
4. Ensure the guidance is clear, prescriptive, and addresses all the failure reasons listed
5. Do NOT modify the detection logic — only the fix guidance text
6. Do NOT commit any changes`;
}
