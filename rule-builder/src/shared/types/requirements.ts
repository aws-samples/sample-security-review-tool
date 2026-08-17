export interface DecisionPoint {
    id: string;
    description: string;
    noFailingCase?: string;
}

export interface RuleRequirement {
    id: string;
    decisionPointId: string;
    description: string;
    expectedBehavior: 'flag' | 'pass';
    rationale: string;
    docReference: string | null;
    settledBy: 'documentation' | 'strict-default' | 'intrinsic-exception';
    evidence: string;
}

export interface RemovedRequirement {
    id: string;
    description: string;
    reason: string;
    conflictedWith?: string;
}

export interface RequirementsSpec {
    ruleId: string;
    generatedAt: string;
    description: string;
    cfnResources: string[];
    tfResources: string[];
    decisionPoints: DecisionPoint[];
    requirements: RuleRequirement[];
    removedRequirements?: RemovedRequirement[];
}
