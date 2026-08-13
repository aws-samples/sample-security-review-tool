import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT = 'lex-001-project';

function buildResource(dataPrivacy: unknown): TerraformResource {
  return {
    type: 'aws_lexv2models_bot',
    name: 'kids',
    address: 'aws_lexv2models_bot.kids',
    values: {
      name: 'kids-bot',
      role_arn: 'arn:aws:iam::123456789012:role/lex-role',
      idle_session_ttl_in_seconds: 300,
      data_privacy: dataPrivacy,
    },
  } as unknown as TerraformResource;
}

function run(dataPrivacy: unknown) {
  const resource = buildResource(dataPrivacy);
  const context: TfContext = { projectName: PROJECT, resource, allResources: [resource] };
  const adapter = new Lex001TfAdapterFactory().bind(context);
  return lex001Control.run(adapter, context);
}

describe('LEX-001 Terraform — conflicting data privacy blocks (REQ-12)', () => {
  // Primary behavior owned by this requirement: conflicting declarations must be flagged.
  it('flags a bot with two data_privacy blocks where one sets child_directed to false', () => {
    const result = run([{ child_directed: true }, { child_directed: false }]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('aws_lexv2models_bot');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.kids');
  });

  it('flags a bot with two data_privacy blocks where one sets child_directed to the string "false"', () => {
    const result = run([{ child_directed: 'true' }, { child_directed: 'false' }]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  // Opposite outcome: nearest input that flips the verdict — every block is child-directed true.
  it('does not flag a bot whose multiple data_privacy blocks all set child_directed to true', () => {
    const result = run([{ child_directed: true }, { child_directed: true }]);

    expect(result).toBeNull();
  });
});
