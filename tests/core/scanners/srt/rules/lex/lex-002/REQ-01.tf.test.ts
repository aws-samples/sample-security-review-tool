import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import type { Lex002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002TfAdapterFactory();

function buildSlot(obfuscationSettingType: string): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name: 'credit_card_number',
    address: 'aws_lexv2models_slot.credit_card_number',
    values: {
      name: 'CreditCardNumber',
      bot_id: 'aws_lexv2models_bot.order_bot',
      bot_version: 'DRAFT',
      locale_id: 'en_US',
      intent_id: 'aws_lexv2models_intent.place_order',
      obfuscation_setting: [
        { obfuscation_setting_type: obfuscationSettingType },
      ],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'lex-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as Lex002Adapter;
  return lex002Control.run(adapter, context);
}

describe('LEX-002 Terraform - slot value obfuscation', () => {
  it('applies to aws_lexv2models_slot resources', () => {
    expect(factory.appliesTo('aws_lexv2models_slot')).toBe(true);
  });

  // Primary behavior for this requirement: DefaultObfuscation is the compliant state.
  it('passes when the slot uses the default obfuscation type', () => {
    const result = runControl(buildSlot('DefaultObfuscation'));
    expect(result).toBeNull();
  });

  // Opposite outcome: same slot, obfuscation present but disabled ("None") must be flagged.
  it('flags a slot whose obfuscation setting type is None', () => {
    const result = runControl(buildSlot('None'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceType).toBe('aws_lexv2models_slot');
    expect(result?.resourceName).toBe('aws_lexv2models_slot.credit_card_number');
  });
});
