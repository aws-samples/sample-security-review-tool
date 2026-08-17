import { describe, expect, it } from 'vitest';
import type { Remediation } from '../../../../src/assess/scanning/remediation/types.js';
import {
  RELATED_RULES_HEADING,
  SecurityControl,
} from '../../../../src/assess/scanning/security-matrix/controls/security-control.js';
import type {
  Finding,
  TfContext,
} from '../../../../src/assess/scanning/security-matrix/controls/types.js';

const FINDINGS = {
  first: {
    issue: 'First issue',
    remediation: 'First remediation',
  },
  second: {
    issue: (adapter: TestAdapter) => `Second issue: ${adapter.detail}`,
    remediation: 'Second remediation',
    manualFixRequired: true,
  },
} as const satisfies Record<string, Finding<TestAdapter>>;

type FindingKey = keyof typeof FINDINGS;

interface TestAdapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly finding: FindingKey | null;
  readonly detail: string;
}

class TestControl extends SecurityControl<TestAdapter, FindingKey> {
  constructor(relatedRules: readonly Remediation[] = []) {
    super({
      id: 'TEST-001',
      priority: 'HIGH',
      description: 'Test control',
      findings: FINDINGS,
      relatedRules,
    });
  }

  protected evaluate(adapter: TestAdapter): FindingKey | null {
    return adapter.finding;
  }
}

const RELATED_FINDINGS = {
  first: {
    issue: 'First related issue',
    remediation: 'First related remediation',
  },
  duplicate: {
    issue: 'Duplicate related issue',
    remediation: 'First related remediation',
  },
  second: {
    issue: 'Second related issue',
    remediation: 'Second related remediation',
  },
} as const satisfies Record<string, Finding<TestAdapter>>;

type RelatedFindingKey = keyof typeof RELATED_FINDINGS;

class RelatedControl extends SecurityControl<TestAdapter, RelatedFindingKey> {
  constructor() {
    super({
      id: 'RELATED-001',
      priority: 'HIGH',
      description: 'Related control',
      findings: RELATED_FINDINGS,
    });
  }

  protected evaluate(): RelatedFindingKey | null {
    return null;
  }
}

const context: TfContext = {
  projectName: 'test-project',
  resource: {
    type: 'test_resource',
    name: 'test',
    address: 'test_resource.test',
    values: {},
  },
  allResources: [],
};

function adapter(finding: FindingKey | null, detail = ''): TestAdapter {
  return {
    resourceId: 'test_resource.test',
    resourceType: 'test_resource',
    finding,
    detail,
  };
}

describe('SecurityControl', () => {
  it('uses the selected finding as the complete scan result definition', () => {
    const result = new TestControl().run(adapter('second', 'adapter context'), context);

    expect(result?.issue).toBe('Second issue: adapter context');
    expect(result?.fix).toBe('Second remediation');
    expect(result?.manualFixRequired).toBe(true);
  });

  it('returns no result when evaluate selects no finding', () => {
    expect(new TestControl().run(adapter(null), context)).toBeNull();
  });

  it('exposes every unique related-control remediation to the primary control', () => {
    const relatedControl = new RelatedControl();
    const externalRule: Remediation = {
      id: 'EXTERNAL-001',
      priority: 'MEDIUM',
      description: 'External rule',
      remediation: 'External remediation',
    };

    expect(relatedControl.remediation).toBe('First related remediation\n\nSecond related remediation');

    const result = new TestControl([relatedControl, externalRule]).run(adapter('first'), context);

    expect(result?.fix).toBe(
      `First remediation${RELATED_RULES_HEADING}` +
      '[RELATED-001] Related control: First related remediation\n\nSecond related remediation\n\n' +
      '[EXTERNAL-001] External rule: External remediation',
    );
  });
});
