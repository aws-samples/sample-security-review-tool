import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001TfAdapterFactory();

function bot(name: string, values: Record<string, unknown>, type = 'aws_lexv2models_bot'): TerraformResource {
  return {
    type,
    name,
    address: `${type}.${name}`,
    values,
  } as unknown as TerraformResource;
}

function assess(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

const compliantSibling = bot('sibling', {
  name: 'sibling-bot',
  role_arn: 'arn:aws:iam::123456789012:role/sibling',
  idle_session_ttl_in_seconds: 300,
  data_privacy: [{ child_directed: true }],
});

describe('LEX-001 (Terraform) - a compliant sibling bot does not cover the assessed bot', () => {
  // Primary behavior owned by REQ-11: per-resource evaluation.
  it('flags an aws_lexv2models_bot with no data_privacy even though a sibling bot sets child_directed = true', () => {
    const assessed = bot('assessed', {
      name: 'assessed-bot',
      role_arn: 'arn:aws:iam::123456789012:role/assessed',
      idle_session_ttl_in_seconds: 300,
    });

    const result = assess(assessed, [assessed, compliantSibling]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.assessed');
    expect(result?.resourceType).toBe('aws_lexv2models_bot');
  });

  it('flags an aws_lex_bot with no child_directed even though a sibling bot sets child_directed = true', () => {
    const assessed = bot('assessed_v1', {
      name: 'assessed-v1-bot',
      child_directed: undefined,
    }, 'aws_lex_bot');

    const result = assess(assessed, [assessed, compliantSibling]);

    expect(result).not.toBeNull();
    expect(result?.resourceType).toBe('aws_lex_bot');
  });

  it('does not flag the assessed bot when the assessed bot itself sets child_directed = true (opposite outcome)', () => {
    const assessed = bot('assessed', {
      name: 'assessed-bot',
      role_arn: 'arn:aws:iam::123456789012:role/assessed',
      idle_session_ttl_in_seconds: 300,
      data_privacy: [{ child_directed: true }],
    });

    expect(assess(assessed, [assessed, compliantSibling])).toBeNull();
  });

  it('still flags the assessed bot when it sets child_directed = false alongside the compliant sibling', () => {
    const assessed = bot('assessed', {
      name: 'assessed-bot',
      role_arn: 'arn:aws:iam::123456789012:role/assessed',
      idle_session_ttl_in_seconds: 300,
      data_privacy: [{ child_directed: false }],
    });

    expect(assess(assessed, [assessed, compliantSibling])).not.toBeNull();
  });
});
