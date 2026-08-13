import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (LEX-001): A child-directed setting expressed as a truthy textual
 * representation of `true` (e.g. the literal text "true", case-insensitively)
 * conveys the same explicit COPPA declaration as a native boolean `true`
 * and must be treated as compliant.
 */

const factory = new Lex001TfAdapterFactory();

function v2Bot(childDirected: unknown): TerraformResource {
  return {
    type: 'aws_lexv2models_bot',
    name: 'coppa',
    address: 'aws_lexv2models_bot.coppa',
    values: {
      name: 'coppa-bot',
      role_arn: 'arn:aws:iam::123456789012:role/lex-role',
      data_privacy: [{ child_directed: childDirected }],
    },
  } as unknown as TerraformResource;
}

function v1Bot(childDirected: unknown): TerraformResource {
  return {
    type: 'aws_lex_bot',
    name: 'coppa',
    address: 'aws_lex_bot.coppa',
    values: {
      name: 'coppa-bot',
      child_directed: childDirected,
    },
  } as unknown as TerraformResource;
}

function context(resource: TerraformResource): TfContext {
  return { projectName: 'test-project', resource, allResources: [resource] };
}

function bind(resource: TerraformResource): Lex001Adapter {
  return factory.bind(context(resource)) as Lex001Adapter;
}

describe('LEX-001 REQ-05 Terraform: textual true for the child-directed setting', () => {
  it.each(['true', 'True', 'TRUE', 'TrUe'])(
    'treats data_privacy.child_directed = %s on aws_lexv2models_bot as compliant',
    (textualTrue) => {
      const resource = v2Bot(textualTrue);
      const adapter = bind(resource);

      expect(adapter.childDirected()).toBe(true);
      expect(lex001Control.run(adapter, context(resource))).toBeNull();
    },
  );

  it.each(['true', 'True', 'TRUE', 'TrUe'])(
    'treats child_directed = %s on aws_lex_bot as compliant',
    (textualTrue) => {
      const resource = v1Bot(textualTrue);
      const adapter = bind(resource);

      expect(adapter.childDirected()).toBe(true);
      expect(lex001Control.run(adapter, context(resource))).toBeNull();
    },
  );

  // Opposite outcome: the nearest input that flips the verdict — the setting is
  // still present as text, but the text does not represent true.
  // Primary behavior for a false declaration is owned by the "missing/false
  // child-directed" requirement; asserted here only to prove this file discriminates.
  it('flags a textual value of "false" as non-compliant', () => {
    const resource = v2Bot('false');
    const adapter = bind(resource);

    expect(adapter.childDirected()).toBe(false);

    const result = lex001Control.run(adapter, context(resource));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.coppa');
    expect(result?.resourceType).toBe('aws_lexv2models_bot');
  });
});
