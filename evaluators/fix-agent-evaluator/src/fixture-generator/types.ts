import type { FixtureFormat, Scanner } from '../../../shared/rule-catalog/src/index.js';

export interface FixtureFile {
    relativePath: string;
    content: string;
}

export interface FixtureMeta {
    checkId: string;
    scanner: Scanner;
    format: FixtureFormat;
    sourceHash: string;
    generatedAt: string;
    validationAttempts: number;
    relatedRuleHashes?: Record<string, string>;
}

export interface GeneratedFixture {
    meta: FixtureMeta;
    fixtureDir: string;
    ungeneratable: boolean;
    ungeneratableReason?: string;
}

export interface ValidationFailure {
    kind: 'parse' | 'synth' | 'scan-missing-target' | 'scan-extra-rules' | 'deps-install-failed';
    message: string;
    details?: string;
    extraCheckIds?: string[];
}

export interface RelatedRuleContext {
    checkId: string;
    description: string;
    ruleBody?: string;
}

export interface ValidationResult {
    ok: boolean;
    failure?: ValidationFailure;
}
