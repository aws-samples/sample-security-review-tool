import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002TfAdapterFactory();

function slotWithObfuscationType(obfuscationSettingType: string): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name: 'card_number',
    address: 'aws_lexv2models_slot.card_number',
    values: {
      name: 'CardNumber',
      bot_id: 'aws_lexv2models_bot.support',
      bot_version: 'DRAFT',
      locale_id: 'en_US',
      intent_id: 'aws_lexv2models_intent.collect_payment',
      obfuscation_setting: [{ obfuscation_setting_type: obfuscationSettingType }],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 Terraform - REQ-02: slot value obfuscation explicitly set to none/disabled', () => {
  // Primary behavior owned by REQ-02: explicit opt-out of obfuscation must be flagged.
  it('flags a slot whose obfuscation_setting_type is None', () => {
    const result = runControl(slotWithObfuscationType('None'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceType).toBe('aws_lexv2models_slot');
    expect(result?.resourceName).toBe('aws_lexv2models_slot.card_number');
    expect(result?.issue).toContain('CardNumber');
  });

  // Opposite outcome: same fixture, obfuscation type present but meeting the standard.
  it('does not flag a slot whose obfuscation_setting_type is DefaultObfuscation', () => {
    const result = runControl(slotWithObfuscationType(DEFAULT_OBFUSCATION));

    expect(result).toBeNull();
  });
});
