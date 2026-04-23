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
}

export interface GeneratedFixture {
    meta: FixtureMeta;
    fixtureDir: string;
    ungeneratable: boolean;
    ungeneratableReason?: string;
}

export interface ValidationFailure {
    kind: 'parse' | 'synth' | 'scan-missing-target' | 'scan-extra-rules';
    message: string;
    details?: string;
}

export interface ValidationResult {
    ok: boolean;
    failure?: ValidationFailure;
}
