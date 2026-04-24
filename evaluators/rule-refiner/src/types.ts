import type { RuleEntry, FixtureFormat, CatalogFilter } from '../../shared/rule-catalog/src/index.js';
import type { ScanResult } from '../../../src/assess/scanning/types.js';

export type { RuleEntry, FixtureFormat, CatalogFilter };
export type { ScanResult };

export interface FindingVariant {
    variantId: string;
    fixGuidance: string;
    label: string;
}

export interface RefinerSession {
    rule: RuleEntry;
    format: FixtureFormat;
    variants: FindingVariant[];
    fixtureDir: string;
    srtRepoRoot: string;
    fixturesRoot: string;
    preFixIssues: Map<string, ScanResult[]>;
    originalRuleSource: string | null;
    result: RefinerResult | null;
}

export type Correctness = 'CORRECT' | 'PARTIAL' | 'INCORRECT';
export type Rating = 'HIGH' | 'MEDIUM' | 'LOW';

export interface Phase1Result {
    correctness: Correctness;
    correctnessReasoning: string;
    awsDocCitations: string[];
    missedCases: string[];
    falsePositiveRisks: string[];
    knownLimitations: string[];
    detectionLogicEdited: boolean;
    editSummary: string;
}

export interface Phase2VariantResult {
    variantId: string;
    format: string;
    effectiveness: Rating;
    effectivenessReasoning: string;
    efficiency: Rating;
    efficiencyReasoning: string;
    rescanPassed: boolean;
    fixGuidanceEdited: boolean;
    editSummary: string;
}

export interface RefinerResult {
    checkId: string;
    phase1: Phase1Result;
    phase2: {
        variantResults: Phase2VariantResult[];
    };
}

export interface FixSessionSummary {
    turns: number;
    applyFixAttempts: number;
    applyFixFailures: number;
    stopReason: string;
    finalComments: string;
}

export interface RescanResult {
    targetRuleStillFires: boolean;
    newRulesTriggered: string[];
    validationPassed: boolean;
    validationError?: string;
}
