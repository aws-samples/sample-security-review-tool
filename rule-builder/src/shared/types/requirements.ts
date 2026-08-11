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

export interface RuleRequirement {
    id: string;
    description: string;
    category: RequirementCategory;
    expectedBehavior: 'flag' | 'pass';
    rationale: string;
}

export interface AmbiguityResolution {
    scenario: string;
    question: string;
    chosenBehavior: 'flag' | 'pass';
    rationale: string;
    docReference: string | null;
    settledBy: 'documentation' | 'strict-default' | 'intrinsic-exception';
}

export interface UnresolvedAmbiguity {
    scenario: string;
    question: string;
}

export interface RemovedRequirement {
    id: string;
    description: string;
    conflictedWith: string;
    reason: string;
}

export interface RequirementsSpec {
    ruleId: string;
    generatedAt: string;
    description: string;
    cfnResources: string[];
    tfResources: string[];
    requirements: RuleRequirement[];
    awsDocReferences: string[];
    resolutions?: AmbiguityResolution[];
    unresolvedAmbiguities?: UnresolvedAmbiguity[];
    removedRequirements?: RemovedRequirement[];
}
