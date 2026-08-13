import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import type { ChildDirectedSetting, Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (Terraform) — owns the "explicit false" behavior of LEX-001:
 * a bot whose child-directed data privacy setting is explicitly false is
 * configured-but-disabled and MUST be flagged.
 */

function v2Resource(childDirected: boolean): TerraformResource {
  return {
    type: 'aws_lexv2models_bot',
    name: 'child_bot',
    address: 'aws_lexv2models_bot.child_bot',
    values: {
      name: 'child-bot',
      role_arn: 'arn:aws:iam::123456789012:role/lex-role',
      idle_session_ttl_in_seconds: 300,
      data_privacy: [{ child_directed: childDirected }],
    },
  } as unknown as TerraformResource;
}

function v1Resource(childDirected: boolean): TerraformResource {
  return {
    type: 'aws_lex_bot',
    name: 'legacy_bot',
    address: 'aws_lex_bot.legacy_bot',
    values: {
      name: 'legacy-bot',
      child_directed: childDirected,
    },
  } as unknown as TerraformResource;
}

function buildContext(resource: TerraformResource): TfContext {
  return {
    projectName: 'lex-project',
    resource,
    allResources: [resource],
  };
}

function buildAdapter(resource: TerraformResource, childDirected: ChildDirectedSetting): Lex001Adapter {
  return {
    resourceId: resource.address,
    resourceType: resource.type,
    childDirected: () => childDirected,
  };
}

describe('LEX-001 REQ-03 (Terraform)', () => {
  it('flags aws_lexv2models_bot with data_privacy child_directed explicitly false', () => {
    const resource = v2Resource(false);
    const result = lex001Control.run(buildAdapter(resource, false), buildContext(resource));

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-001');
    expect(result!.resourceType).toBe('aws_lexv2models_bot');
    expect(result!.resourceName).toBe('aws_lexv2models_bot.child_bot');
  });

  it('flags aws_lex_bot with child_directed explicitly false', () => {
    const resource = v1Resource(false);
    const result = lex001Control.run(buildAdapter(resource, false), buildContext(resource));

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-001');
    expect(result!.resourceType).toBe('aws_lex_bot');
  });

  // Opposite outcome: nearest input that flips the verdict — the same setting present but true.
  it('does not flag aws_lexv2models_bot with data_privacy child_directed explicitly true', () => {
    const resource = v2Resource(true);
    const result = lex001Control.run(buildAdapter(resource, true), buildContext(resource));

    expect(result).toBeNull();
  });
});
