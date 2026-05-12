import type { ValidationDiagnostics } from '../requirement-implementation/types.js';

export interface GeneratedFixture {
    requirementId: string;
    templateSnippet: string;
    resourceTypes: string[];
    generationAttempt: number;
}

export interface FixtureRegenerationContext {
    previousFixture: string;
    failureDiagnostics: ValidationDiagnostics;
}
