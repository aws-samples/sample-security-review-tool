import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (AS-001): Auto Scaling Groups must have a default cooldown period configured
 * (set to a nonzero value).
 *
 * Scenario: `default_cooldown = var.cooldown` where the variable is declared in the same file with
 * `default = 0` and no value is supplied. The source reader resolves same-file variable defaults
 * (zero survives), so the rule sees `default_cooldown: 0` — an explicitly disabled cooldown.
 */

const factory = new As001TfAdapterFactory();

function buildResource(cooldown: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 1,
      max_size: 3,
      default_cooldown: cooldown,
      launch_template: [{ id: 'aws_launch_template.lt' }],
    },
  } as unknown as TerraformResource;
}

function run(cooldown: unknown) {
  const resource = buildResource(cooldown);
  const context: TfContext = { projectName: 'asg-project', resource, allResources: [resource] };
  return as001Control.run(factory.bind(context), context);
}

describe('AS-001 Terraform - cooldown from a variable defaulting to zero', () => {
  it('flags the group when the variable default resolves to zero', () => {
    const result = run(0);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.issue).toMatch(/zero/i);
  });

  it('flags the group when the variable default resolves to the string "0"', () => {
    const result = run('0');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: nearest input that flips the verdict — the variable still supplies the
  // cooldown, but its default is a usable nonzero duration.
  it('does not flag the group when the variable default resolves to a nonzero value', () => {
    expect(run(300)).toBeNull();
  });
});
