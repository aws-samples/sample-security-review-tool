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

export interface RequirementsSpec {
    ruleId: string;
    generatedAt: string;
    description: string;
    requirements: RuleRequirement[];
    awsDocReferences: string[];
}
