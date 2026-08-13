import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002TfAdapterFactory();

function slotResource(name: string, localeId: string, obfuscationType: string): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name,
    address: `aws_lexv2models_slot.${name}`,
    values: {
      name,
      // reference form: bot id wired from the bot resource in HCL
      bot_id: 'aws_lexv2models_bot.customer_service',
      bot_version: 'DRAFT',
      locale_id: localeId,
      intent_id: 'aws_lexv2models_intent.collect_card_details',
      slot_type_id: 'AMAZON.AlphaNumeric',
      obfuscation_setting: [{ obfuscation_setting_type: obfuscationType }],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'lex-project',
    resource,
    allResources,
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 Terraform — slot value obfuscation', () => {
  // Primary behavior owned by LEX-002 (REQ-06): all slots across all locales/intents obfuscated -> pass
  it('passes for every slot when all locales and intents enable obfuscation', () => {
    const slots = [
      slotResource('card_number', 'en_US', DEFAULT_OBFUSCATION),
      slotResource('card_pin', 'en_US', DEFAULT_OBFUSCATION),
      slotResource('numero_tarjeta', 'es_US', DEFAULT_OBFUSCATION),
    ];

    const results = slots.map(slot => runControl(slot, slots));

    expect(results).toEqual([null, null, null]);
  });

  // Opposite outcome: identical fixtures except obfuscation type is present but set to the disabled value
  it('flags a slot whose obfuscation type is None instead of masking', () => {
    const slots = [
      slotResource('card_number', 'en_US', 'None'),
      slotResource('card_pin', 'en_US', DEFAULT_OBFUSCATION),
      slotResource('numero_tarjeta', 'es_US', DEFAULT_OBFUSCATION),
    ];

    const results = slots.map(slot => runControl(slot, slots));

    expect(results[0]).not.toBeNull();
    expect(results[0]?.check_id).toBe('LEX-002');
    expect(results[0]?.resourceName).toBe('aws_lexv2models_slot.card_number');
    expect(results[0]?.issue).toContain('card_number');
    expect(results[1]).toBeNull();
    expect(results[2]).toBeNull();
  });
});
