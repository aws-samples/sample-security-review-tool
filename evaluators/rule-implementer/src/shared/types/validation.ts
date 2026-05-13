export type FailureCause =
    | 'rule_logic'
    | 'fixture_missing_resource'
    | 'fixture_parse_error'
    | 'fixture_wrong_structure'
    | 'value_mismatch'
    | 'cross_resource_not_found'
    | 'intrinsic_not_handled'
    | 'unknown';

export interface ValidationDiagnostics {
    ruleWasInvoked: boolean;
    matchedResourceTypes: string[];
    templateResourceTypes: string[];
    evaluationError?: string;
    parseError?: string;
    fixtureStructureValid: boolean;
    suggestedCause: FailureCause;
    resolvedTemplate?: string;
}

export interface ValidationResult {
    requirementId: string;
    passed: boolean;
    expected: 'flag' | 'pass';
    actual: 'flag' | 'pass' | 'error';
    diagnostics: ValidationDiagnostics;
}
