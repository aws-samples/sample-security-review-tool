import z from 'zod';
import { RequirementsOutputSchema } from './requirements-schema.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';

type Draft = z.infer<typeof RequirementsOutputSchema>;
type DraftRequirement = Draft['requirements'][number];

const FORMAT_MARKERS = [
    { pattern: /AWS::/, label: 'a CloudFormation resource type or pseudo-parameter' },
    { pattern: /Fn::/, label: 'a CloudFormation intrinsic function' },
    { pattern: /!(?:Ref|GetAtt|Sub|Join|If|Select|Split|ImportValue)\b/, label: 'a CloudFormation short-form intrinsic' },
    { pattern: /\baws_[a-z0-9_]+/, label: 'a Terraform resource type' },
    { pattern: /\$\{/, label: 'a template interpolation' },
];

const VERDICT_WORDS = [
    /\bcorrectly\b/i,
    /\bproperly\b/i,
    /\binsufficient(ly)?\b/i,
    /\bviolat(es|ing|ion)\b/i,
    /\bnon-?compliant\b/i,
    /\bcompliant\b/i,
];

export function auditDraft(draft: Draft): string[] {
    return [
        ...uncoveredDecisionPoints(draft),
        ...undeclaredDecisionPoints(draft),
        ...duplicateIds(draft.requirements),
        ...duplicateDescriptions(draft.requirements),
        ...formatSpecificDescriptions(draft.requirements),
        ...verdictLadenDescriptions(draft.requirements),
    ];
}

export function auditResolved(spec: RequirementsSpec): string[] {
    return [
        ...uncoveredDecisionPoints(spec),
        ...missingDiscrimination(spec),
        ...uncitedNonDefaults(spec),
    ];
}

/**
 * Decision points every one of whose scenarios passes. Either the group is genuinely all-pass or
 * it is missing the configuration that matters, and the finished specification looks the same
 * both ways — so each one is asked about rather than assumed complete.
 */
export function decisionPointsWithoutFailure<T extends { id: string }>(
    decisionPoints: T[],
    requirements: { decisionPointId: string; expectedBehavior: 'flag' | 'pass' }[],
): T[] {
    const failing = new Set(requirements
        .filter(requirement => requirement.expectedBehavior === 'flag')
        .map(requirement => requirement.decisionPointId));

    return decisionPoints.filter(decisionPoint => !failing.has(decisionPoint.id));
}

function uncoveredDecisionPoints(draft: { decisionPoints: Draft['decisionPoints']; requirements: { decisionPointId: string }[] }): string[] {
    const cited = new Set(draft.requirements.map(requirement => requirement.decisionPointId));

    return draft.decisionPoints
        .filter(decisionPoint => !cited.has(decisionPoint.id))
        .map(decisionPoint => `${decisionPoint.id} ("${decisionPoint.description}") has no scenario exercising it. Either enumerate its states or drop it as not a decision point.`);
}

function undeclaredDecisionPoints(draft: Draft): string[] {
    const declared = new Set(draft.decisionPoints.map(decisionPoint => decisionPoint.id));

    return draft.requirements
        .filter(requirement => !declared.has(requirement.decisionPointId))
        .map(requirement => `${requirement.id} cites ${requirement.decisionPointId || 'no decision point'}, which is not declared. A scenario with no decision point behind it is out of scope.`);
}

function duplicateIds(requirements: DraftRequirement[]): string[] {
    return [...duplicatesBy(requirements, requirement => requirement.id).keys()]
        .map(id => `${id} is used by more than one scenario.`);
}

function duplicateDescriptions(requirements: DraftRequirement[]): string[] {
    return [...duplicatesBy(requirements, requirement => normalize(requirement.description)).values()]
        .map(group => `${group.map(requirement => requirement.id).join(' and ')} describe the same configuration. Keep one, or narrow them so they describe different configurations.`);
}

function formatSpecificDescriptions(requirements: DraftRequirement[]): string[] {
    return requirements.flatMap(requirement => FORMAT_MARKERS
        .filter(marker => marker.pattern.test(requirement.description))
        .map(marker => `${requirement.id} names ${marker.label} in its description ("${requirement.description}"). Describe the configuration, not the format.`));
}

function verdictLadenDescriptions(requirements: DraftRequirement[]): string[] {
    return requirements.flatMap(requirement => VERDICT_WORDS
        .map(word => word.exec(requirement.description))
        .filter((match): match is RegExpExecArray => match !== null)
        .map(match => `${requirement.id} calls its configuration "${match[0]}", which is a verdict. Describe the configuration and leave the verdict to the research step.`));
}

function missingDiscrimination(spec: RequirementsSpec): string[] {
    const outcomes = new Set(spec.requirements.map(requirement => requirement.expectedBehavior));
    if (outcomes.size !== 1) return [];

    const only = [...outcomes][0];
    return [`Every requirement expects '${only}', so a rule that always answers '${only}' satisfies the whole specification.`];
}

function uncitedNonDefaults(spec: RequirementsSpec): string[] {
    return spec.requirements
        .filter(requirement => requirement.settledBy === 'documentation' && requirement.docReference === null)
        .map(requirement => `${requirement.id} claims documentation settled it but cites none.`);
}

/** Keys shared by more than one item, each mapped to the items that share it. */
function duplicatesBy<T>(items: T[], key: (item: T) => string): Map<string, T[]> {
    const grouped = new Map<string, T[]>();
    for (const item of items) grouped.set(key(item), [...(grouped.get(key(item)) ?? []), item]);

    return new Map([...grouped].filter(([, group]) => group.length > 1));
}

function normalize(description: string): string {
    return description.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}
