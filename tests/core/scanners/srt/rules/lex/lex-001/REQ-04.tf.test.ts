import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001TfAdapterFactory();

function buildResource(type: string, values: Record<string, unknown>): TerraformResource {
  return {
    type,
    name: 'my_bot',
    address: `${type}.my_bot`,
    values,
  } as unknown as TerraformResource;
}

function scan(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

describe('LEX-001 REQ-04 (Terraform): data_privacy block present but no child_directed value', () => {
  // Primary behavior owned by this requirement: empty data_privacy block => flag.
  it('flags aws_lexv2models_bot whose data_privacy block has no child_directed value', () => {
    const result = scan(
      buildResource('aws_lexv2models_bot', {
        name: 'my-bot',
        role_arn: 'arn:aws:iam::123456789012:role/bot-role',
        idle_session_ttl_in_seconds: 300,
        data_privacy: [{}],
      }),
    );

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-001');
    expect(result!.resourceType).toBe('aws_lexv2models_bot');
    expect(result!.resourceName).toBe('aws_lexv2models_bot.my_bot');
  });

  it('flags aws_lexv2models_bot whose data_privacy block is an empty object rather than a list', () => {
    const result = scan(
      buildResource('aws_lexv2models_bot', {
        name: 'my-bot',
        role_arn: 'arn:aws:iam::123456789012:role/bot-role',
        data_privacy: {},
      }),
    );

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-001');
  });

  // aws_lex_bot has no data privacy configuration block at all — child_directed is a flat
  // top-level argument — so "configuration present but containing no child-directed value"
  // cannot be represented for this resource type without inventing a fixture.
  it.skip('aws_lex_bot cannot represent an empty data privacy configuration', () => {});

  // Opposite outcome: nearest input that flips the verdict — same data_privacy block,
  // but with child_directed explicitly declared true.
  it('does not flag aws_lexv2models_bot whose data_privacy block declares child_directed true', () => {
    const result = scan(
      buildResource('aws_lexv2models_bot', {
        name: 'my-bot',
        role_arn: 'arn:aws:iam::123456789012:role/bot-role',
        idle_session_ttl_in_seconds: 300,
        data_privacy: [{ child_directed: true }],
      }),
    );

    expect(result).toBeNull();
  });
});
