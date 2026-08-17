import { describe, expect, it } from 'vitest';
import { auditDraft, auditResolved, decisionPointsWithoutFailure } from '../../../rule-builder/src/requirements/requirements-audit.js';
import type { RequirementsSpec, RuleRequirement } from '../../../rule-builder/src/shared/types/requirements.js';

const DECISION_POINTS = [
  { id: 'DP-1', description: 'whether a default cooldown is declared' },
  { id: 'DP-2', description: 'the declared cooldown value against the threshold' },
];

function scenario(id: string, decisionPointId: string, description: string) {
  return { id, decisionPointId, description };
}

function draft(requirements: ReturnType<typeof scenario>[], decisionPoints = DECISION_POINTS) {
  return { decisionPoints, requirements, cfnResources: ['AWS::AutoScaling::AutoScalingGroup'], tfResources: ['aws_autoscaling_group'] };
}

const SOUND_LIST = draft([
  scenario('REQ-01', 'DP-1', 'Auto Scaling group declares no default cooldown'),
  scenario('REQ-02', 'DP-2', 'Auto Scaling group declares a default cooldown of zero seconds'),
]);

function requirement(id: string, expectedBehavior: 'flag' | 'pass', overrides: Partial<RuleRequirement> = {}): RuleRequirement {
  return {
    id,
    decisionPointId: 'DP-1',
    description: `configuration ${id}`,
    expectedBehavior,
    rationale: 'the service applies no default, so the protection is absent',
    docReference: 'https://docs.aws.amazon.com/example.html',
    settledBy: 'documentation',
    evidence: 'searched the resource reference and found no default',
    ...overrides,
  };
}

function spec(requirements: RuleRequirement[]): RequirementsSpec {
  return {
    ruleId: 'AS-001',
    generatedAt: '2026-08-14T00:00:00.000Z',
    description: 'Auto Scaling Groups must have a default cooldown period configured',
    cfnResources: [],
    tfResources: [],
    decisionPoints: DECISION_POINTS,
    requirements,
  };
}

describe('auditDraft', () => {
  it('passes a list that covers every decision point', () => {
    expect(auditDraft(SOUND_LIST)).toEqual([]);
  });

  it('reports a decision point no scenario exercises', () => {
    const problems = auditDraft(draft([scenario('REQ-01', 'DP-1', 'group declares no default cooldown')]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('DP-2');
    expect(problems[0]).toContain('has no scenario exercising it');
  });

  it('reports a scenario citing a decision point that was never declared', () => {
    const problems = auditDraft(draft([...SOUND_LIST.requirements, scenario('REQ-03', 'DP-9', 'group enables scale-in protection')]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('REQ-03 cites DP-9, which is not declared');
  });

  it('reports a description naming a CloudFormation resource type', () => {
    const problems = auditDraft(draft([
      scenario('REQ-01', 'DP-1', 'AWS::AutoScaling::AutoScalingGroup omits the Cooldown property'),
      scenario('REQ-02', 'DP-2', 'group declares a cooldown of zero seconds'),
    ]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('REQ-01 names a CloudFormation resource type');
  });

  it('reports a description naming a Terraform resource type or an interpolation', () => {
    const problems = auditDraft(draft([
      scenario('REQ-01', 'DP-1', 'aws_autoscaling_group declares no cooldown'),
      scenario('REQ-02', 'DP-2', 'cooldown is ${var.cooldown}'),
    ]));

    expect(problems).toHaveLength(2);
    expect(problems[0]).toContain('REQ-01 names a Terraform resource type');
    expect(problems[1]).toContain('REQ-02 names a template interpolation');
  });

  it('reports a description that states a verdict instead of a configuration', () => {
    const problems = auditDraft(draft([
      scenario('REQ-01', 'DP-1', 'group is correctly configured with a cooldown'),
      scenario('REQ-02', 'DP-2', 'group has an insufficient cooldown of zero seconds'),
    ]));

    expect(problems).toHaveLength(2);
    expect(problems[0]).toContain('REQ-01 calls its configuration "correctly"');
    expect(problems[1]).toContain('REQ-02 calls its configuration "insufficient"');
  });

  it('reports two scenarios sharing an id', () => {
    const problems = auditDraft(draft([
      scenario('REQ-01', 'DP-1', 'group declares no default cooldown'),
      scenario('REQ-01', 'DP-2', 'group declares a cooldown of zero seconds'),
    ]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('REQ-01 is used by more than one scenario');
  });

  it('reports two scenarios describing the same configuration', () => {
    const problems = auditDraft(draft([
      scenario('REQ-01', 'DP-1', 'group declares no default cooldown'),
      scenario('REQ-02', 'DP-2', 'Group declares no default cooldown.'),
    ]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('REQ-01 and REQ-02 describe the same configuration');
  });
});

describe('auditResolved', () => {
  it('passes a specification with both outcomes and cited research', () => {
    expect(auditResolved(spec([
      requirement('REQ-01', 'flag'),
      requirement('REQ-02', 'pass', { decisionPointId: 'DP-2' }),
    ]))).toEqual([]);
  });

  it('reports a specification whose every requirement expects the same outcome', () => {
    const problems = auditResolved(spec([
      requirement('REQ-01', 'flag'),
      requirement('REQ-02', 'flag', { decisionPointId: 'DP-2' }),
    ]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("always answers 'flag'");
  });

  it('reports research that claims documentation but cites none', () => {
    const problems = auditResolved(spec([
      requirement('REQ-01', 'flag', { docReference: null }),
      requirement('REQ-02', 'pass', { decisionPointId: 'DP-2' }),
    ]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('REQ-01 claims documentation settled it but cites none');
  });

  it('accepts a strict-default verdict with no citation', () => {
    expect(auditResolved(spec([
      requirement('REQ-01', 'flag', { settledBy: 'strict-default', docReference: null }),
      requirement('REQ-02', 'pass', { decisionPointId: 'DP-2' }),
    ]))).toEqual([]);
  });

  it('reports a decision point left uncovered after removals', () => {
    const problems = auditResolved(spec([requirement('REQ-01', 'flag'), requirement('REQ-02', 'pass')]));

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('DP-2');
  });
});

describe('decisionPointsWithoutFailure', () => {
  it('names a decision point whose every scenario passes, even when other decision points fail', () => {
    const gaps = decisionPointsWithoutFailure(DECISION_POINTS, [
      requirement('REQ-01', 'flag'),
      requirement('REQ-02', 'pass', { decisionPointId: 'DP-2' }),
      requirement('REQ-03', 'pass', { decisionPointId: 'DP-2' }),
    ]);

    expect(gaps.map(decisionPoint => decisionPoint.id)).toEqual(['DP-2']);
  });

  it('names nothing when every decision point has a failing scenario', () => {
    expect(decisionPointsWithoutFailure(DECISION_POINTS, [
      requirement('REQ-01', 'flag'),
      requirement('REQ-02', 'flag', { decisionPointId: 'DP-2' }),
    ])).toEqual([]);
  });

  it('names a decision point with no scenarios at all', () => {
    const gaps = decisionPointsWithoutFailure(DECISION_POINTS, [requirement('REQ-01', 'flag')]);

    expect(gaps.map(decisionPoint => decisionPoint.id)).toEqual(['DP-2']);
  });
});
