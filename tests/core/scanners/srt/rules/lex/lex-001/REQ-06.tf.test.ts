import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-06 (Terraform): LEX-001 owns this behavior. A child-directed value that does not
// resolve to true (e.g. 'yes', 'no', a number, or an empty value) must be flagged.

const factory = new Lex001TfAdapterFactory();

function v2Bot(childDirected: unknown): TerraformResource {
  return {
    type: 'aws_lexv2models_bot',
    name: 'kids',
    address: 'aws_lexv2models_bot.kids',
    values: {
      name: 'kids-bot',
      role_arn: 'arn:aws:iam::123456789012:role/lex-role',
      idle_session_ttl_in_seconds: 300,
      data_privacy: [{ child_directed: childDirected }],
    },
  } as unknown as TerraformResource;
}

function v1Bot(childDirected: unknown): TerraformResource {
  return {
    type: 'aws_lex_bot',
    name: 'kids',
    address: 'aws_lex_bot.kids',
    values: {
      name: 'kids_bot',
      child_directed: childDirected,
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

describe('LEX-001 REQ-06 Terraform: child_directed value that does not resolve to true', () => {
  it("flags aws_lexv2models_bot with textual value 'yes'", () => {
    const result = run(v2Bot('yes'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('aws_lexv2models_bot');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.kids');
  });

  it("flags aws_lexv2models_bot with textual value 'no'", () => {
    expect(run(v2Bot('no'))).not.toBeNull();
  });

  it('flags aws_lexv2models_bot with a numeric value of 1', () => {
    expect(run(v2Bot(1))).not.toBeNull();
  });

  it('flags aws_lexv2models_bot with an empty string value', () => {
    expect(run(v2Bot(''))).not.toBeNull();
  });

  it("flags aws_lex_bot with textual value 'yes'", () => {
    const result = run(v1Bot('yes'));
    expect(result).not.toBeNull();
    expect(result?.resourceType).toBe('aws_lex_bot');
  });

  it('flags aws_lex_bot with a numeric value of 0', () => {
    expect(run(v1Bot(0))).not.toBeNull();
  });

  it('flags aws_lex_bot with an empty string value', () => {
    expect(run(v1Bot(''))).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the value resolves to true.
  it('does not flag aws_lexv2models_bot when the value resolves to true (boolean)', () => {
    expect(run(v2Bot(true))).toBeNull();
  });

  it("does not flag aws_lex_bot when the value resolves to true (recognized text 'true')", () => {
    expect(run(v1Bot('true'))).toBeNull();
  });
});
