import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAutoScalingGroup';

/**
 * REQ-10 (AS-001): an Auto Scaling group whose Cooldown references a template
 * parameter carrying a nonzero default resolves, at analysis time, to that
 * nonzero default. `parseCfnTemplate` substitutes the parameter's Default before
 * the rule runs, so the fixtures below hold the post-preprocessing value.
 */
function buildTemplate(resolvedCooldown: unknown): Template {
  return {
    Parameters: {
      CooldownSeconds: {
        Type: 'String',
        Default: String(resolvedCooldown),
      },
    },
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          // Authored as { Ref: 'CooldownSeconds' }; preprocessing replaces it
          // with the parameter's Default value.
          Cooldown: resolvedCooldown,
        },
      },
    },
  } as unknown as Template;
}

function run(resolvedCooldown: unknown): ScanResult | null {
  const template = buildTemplate(resolvedCooldown);
  const context: CfnContext = {
    stackName: 'as-001-stack',
    template,
    resource: (template.Resources as Record<string, never>)[LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
  const adapter = new As001CfnAdapterFactory().bind(context) as As001Adapter;
  return as001Control.run(adapter, context);
}

describe('AS-001 CloudFormation — cooldown from a template parameter default', () => {
  it('passes when the referenced parameter default resolves to a nonzero cooldown', () => {
    expect(run('300')).toBeNull();
  });

  // Opposite outcome: same parameter reference, but its default is zero, which
  // is the zero-cooldown breach owned by AS-001.
  it('flags when the referenced parameter default resolves to a zero cooldown', () => {
    const result = run('0');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
