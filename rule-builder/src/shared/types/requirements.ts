export type RequirementCategory =
    | 'ABSENT'
    | 'WRONG_TARGET'
    | 'DISABLED'
    | 'PARTIAL_COVERAGE'
    | 'EXPLICIT_EXCLUSION'
    | 'INTRINSIC_UNRESOLVABLE'
    | 'MIXED_CONFIG'
    | 'EMPTY_COLLECTION'
    | 'WILDCARD_MATCH'
    | 'SPECIFIC_RESOURCE';

// The requirement's own expectedBehavior and rationale are this question's answer, so neither is
// repeated here. What remains is where the answer came from and the long-form evidence for it.
export interface Ambiguity {
    question: string;
    settledBy: 'documentation' | 'strict-default' | 'intrinsic-exception';
    docReference: string | null;
    evidence: string;
}

export interface RuleRequirement {
    id: string;
    description: string;
    category: RequirementCategory;
    expectedBehavior: 'flag' | 'pass';
    rationale: string;
    ambiguity?: Ambiguity;
}

export interface RemovedRequirement {
    id: string;
    description: string;
    conflictedWith: string;
    reason: string;
    ambiguity?: Ambiguity;
}

export interface RequirementsSpec {
    ruleId: string;
    generatedAt: string;
    description: string;
    cfnResources: string[];
    tfResources: string[];
    requirements: RuleRequirement[];
    removedRequirements?: RemovedRequirement[];
}
