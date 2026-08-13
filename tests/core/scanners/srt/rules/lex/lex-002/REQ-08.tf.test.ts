import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (LEX-002): obfuscation_setting_type is statically the disabled value while an
 * unrelated slot argument is unknown at plan time (null). The finding is certain, so flag.
 */
function buildSlot(obfuscationType: string): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name: 'ssn',
    address: 'aws_lexv2models_slot.ssn',
    values: {
      name: 'SocialSecurityNumber',
      bot_id: 'aws_lexv2models_bot.support',
      intent_id: 'aws_lexv2models_intent.collect_pii',
      locale_id: 'en_US',
      // Unrelated argument unknown at plan time.
      description: null,
      obfuscation_setting: [{ obfuscation_setting_type: obfuscationType }],
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = new Lex002TfAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 REQ-08 (Terraform)', () => {
  it('flags a slot with obfuscation fixed to None even though an unrelated argument is unknown', () => {
    const result = run(buildSlot('None'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe('aws_lexv2models_slot.ssn');
    expect(result?.resourceType).toBe('aws_lexv2models_slot');
    expect(result?.issue).toContain('SocialSecurityNumber');
  });

  // Opposite outcome: same fixture, only the obfuscation type flips to the enabled value.
  it('does not flag when obfuscation is DefaultObfuscation despite the same unknown argument', () => {
    const result = run(buildSlot(DEFAULT_OBFUSCATION));

    expect(result).toBeNull();
  });
});
