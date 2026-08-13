import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001TfAdapterFactory();

function v2Bot(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_lexv2models_bot',
    name: 'kids',
    address: 'aws_lexv2models_bot.kids',
    values: { name: 'kids-bot', idle_session_ttl_in_seconds: 300, ...values },
  } as unknown as TerraformResource;
}

function v1Bot(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_lex_bot',
    name: 'kids',
    address: 'aws_lex_bot.kids',
    values: { name: 'kids_bot', ...values },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  return lex001Control.run(factory.bind(context), context);
}

describe('LEX-001 REQ-07 (Terraform): unresolvable child-directed value', () => {
  it('passes when aws_lexv2models_bot data_privacy.child_directed is unknown at plan time (null)', () => {
    const result = run(v2Bot({ data_privacy: [{ child_directed: null }] }));
    expect(result).toBeNull();
  });

  it('passes when aws_lex_bot child_directed is unknown at plan time (null)', () => {
    const result = run(v1Bot({ child_directed: null }));
    expect(result).toBeNull();
  });

  // Opposite outcome: primary behavior owned by the "explicitly true" requirement.
  // Nearest input that flips the verdict — the value is present and resolvable, but false.
  it('flags aws_lexv2models_bot when child_directed resolves to false', () => {
    const result = run(v2Bot({ data_privacy: [{ child_directed: false }] }));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.kids');
    expect(result?.resourceType).toBe('aws_lexv2models_bot');
  });
});
