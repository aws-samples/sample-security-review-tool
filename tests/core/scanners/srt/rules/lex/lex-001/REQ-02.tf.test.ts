import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function resource(type: string, values: Record<string, unknown>): TerraformResource {
  return {
    type,
    name: 'child_bot',
    address: `${type}.child_bot`,
    values,
  } as unknown as TerraformResource;
}

function run(res: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: res,
    allResources: [res],
  };
  const adapter = new Lex001TfAdapterFactory().bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

describe('LEX-001 REQ-02 (Terraform): data privacy child-directed explicitly true', () => {
  it('applies to both Lex bot resource types', () => {
    const factory = new Lex001TfAdapterFactory();
    expect(factory.appliesTo('aws_lexv2models_bot')).toBe(true);
    expect(factory.appliesTo('aws_lex_bot')).toBe(true);
  });

  // Primary behavior owned by this requirement: explicit true is compliant.
  it('passes when aws_lexv2models_bot data_privacy block sets child_directed = true', () => {
    const result = run(resource('aws_lexv2models_bot', {
      name: 'child-bot',
      role_arn: 'arn:aws:iam::123456789012:role/lex',
      idle_session_ttl_in_seconds: 300,
      data_privacy: [{ child_directed: true }],
    }));

    expect(result).toBeNull();
  });

  it('passes when aws_lexv2models_bot data_privacy is an object with child_directed = true', () => {
    const result = run(resource('aws_lexv2models_bot', {
      name: 'child-bot',
      role_arn: 'arn:aws:iam::123456789012:role/lex',
      data_privacy: { child_directed: true },
    }));

    expect(result).toBeNull();
  });

  it('passes when aws_lex_bot sets child_directed = true', () => {
    const result = run(resource('aws_lex_bot', {
      name: 'child-bot',
      child_directed: true,
    }));

    expect(result).toBeNull();
  });

  // Opposite outcome: setting is present but declares a non-compliant value.
  it('flags when aws_lexv2models_bot data_privacy sets child_directed = false', () => {
    const result = run(resource('aws_lexv2models_bot', {
      name: 'child-bot',
      role_arn: 'arn:aws:iam::123456789012:role/lex',
      idle_session_ttl_in_seconds: 300,
      data_privacy: [{ child_directed: false }],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.child_bot');
    expect(result?.resourceType).toBe('aws_lexv2models_bot');
  });

  // Opposite outcome for the v1 resource shape.
  it('flags when aws_lex_bot sets child_directed = false', () => {
    const result = run(resource('aws_lex_bot', {
      name: 'child-bot',
      child_directed: false,
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });
});
