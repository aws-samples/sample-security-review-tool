export type Correctness = 'CORRECT' | 'PARTIAL' | 'INCORRECT';

export interface RuleImplVerdict {
    checkId: string;
    ruleDescription: string;
    correctness: Correctness;
    correctnessReasoning: string;
    awsDocCitations: string[];
    missedCases: string[];
    falsePositiveRisks: string[];
    suggestedLogicChanges: string;
    ruleSourceHash: string;
}

export interface ReviewerSession {
    verdict: RuleImplVerdict | null;
}
