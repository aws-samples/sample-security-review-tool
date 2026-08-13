import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002TfAdapterFactory();

function slot(name: string, obfuscationType: string): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name,
    address: `aws_lexv2models_slot.${name}`,
    values: {
      name,
      // Reference form: bot_id / bot_version wired from the bot resource in HCL.
      bot_id: 'aws_lexv2models_bot.order_bot',
      bot_version: 'aws_lexv2models_bot_version.order_bot_version',
      intent_id: 'aws_lexv2models_intent.place_order',
      slot_type_id: 'AMAZON.AlphaNumeric',
      obfuscation_setting: [{ obfuscation_setting_type: obfuscationType }],
    },
  } as unknown as TerraformResource;
}

function run(target: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = { projectName: 'lex-project', resource: target, allResources };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 Terraform - obfuscation must be enabled on every bot slot', () => {
  const cardNumber = slot('card_number', DEFAULT_OBFUSCATION);
  const securityCode = slot('security_code', 'None');
  const zipCode = slot('zip_code', DEFAULT_OBFUSCATION);
  const allResources = [cardNumber, securityCode, zipCode];

  // Primary behavior owned by LEX-002: the disabled slot is flagged even though siblings are obfuscated.
  it('flags the slot with obfuscation disabled among sibling slots of the same bot', () => {
    const result = run(securityCode, allResources);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-002');
    expect(result!.resourceType).toBe('aws_lexv2models_slot');
    expect(result!.resourceName).toBe('aws_lexv2models_slot.security_code');
    expect(result!.issue).toContain('security_code');
  });

  // Opposite outcome: sibling slots of the same bot that keep obfuscation enabled must not be flagged.
  it('does not flag sibling slots of the same bot that have obfuscation enabled', () => {
    expect(run(cardNumber, allResources)).toBeNull();
    expect(run(zipCode, allResources)).toBeNull();
  });
});
