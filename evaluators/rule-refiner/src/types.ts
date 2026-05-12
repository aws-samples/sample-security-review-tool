import type { RuleEntry, FixtureFormat, CatalogFilter } from './shared/rule-catalog/index.js';

export type { RuleEntry, FixtureFormat, CatalogFilter };

export interface FindingVariant {
    variantId: string;
    fixGuidance: string;
    label: string;
}
