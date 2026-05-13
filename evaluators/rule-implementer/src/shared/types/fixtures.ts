import type { ValidationDiagnostics } from './validation.js';
import type { RuleRequirement } from './requirements.js';

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

export interface FixtureSet {
    requirement: RuleRequirement;
    fixture: GeneratedFixture;
}
