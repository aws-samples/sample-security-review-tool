export type Scanner = 'security-matrix' | 'checkov' | 'bandit' | 'semgrep';

export type FixtureFormat = 'cfn' | 'cdk' | 'terraform' | 'python' | 'javascript' | 'go' | 'java' | 'yaml';

export interface RuleEntry {
    checkId: string;
    scanner: Scanner;
    service?: string;
    priority: 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    fixGuidance: string;
    sourceLocation: string;
    sourceHash: string;
    applicableResourceTypes?: string[];
    applicableFormats: FixtureFormat[];
    ruleBody: string;
}

export interface CatalogFilter {
    checkId?: string;
    scanner?: Scanner;
    service?: string;
}
