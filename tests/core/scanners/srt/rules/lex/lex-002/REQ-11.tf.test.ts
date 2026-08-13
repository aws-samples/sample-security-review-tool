import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (LEX-002): A conversational bot has obfuscation disabled on a slot while
 * conversation logging for the bot is not enabled / is explicitly turned off.
 * Expected: flag — obfuscation must be set on the slot itself; alias-level logging
 * can be toggled independently at any time.
 */

const factory = new Lex002TfAdapterFactory();

const bot: TerraformResource = {
  type: 'aws_lexv2models_bot',
  name: 'payment',
  address: 'aws_lexv2models_bot.payment',
  values: { name: 'PaymentBot' },
} as unknown as TerraformResource;

/** Alias with conversation logging explicitly disabled. */
const aliasLoggingOff: TerraformResource = {
  type: 'aws_lexv2models_bot_alias',
  name: 'live',
  address: 'aws_lexv2models_bot_alias.live',
  values: {
    bot_id: 'aws_lexv2models_bot.payment',
    bot_alias_name: 'live',
    conversation_log_settings: [
      {
        text_log_settings: [
          {
            enabled: false,
            destination: [{ cloudwatch: [{ cloudwatch_log_group_arn: 'arn:aws:logs:us-east-1:123456789012:log-group:/lex', log_prefix: 'lex/' }] }],
          },
        ],
      },
    ],
  },
} as unknown as TerraformResource;

function buildSlot(obfuscationSetting: unknown, botIdValue: string): TerraformResource {
  const values: Record<string, unknown> = {
    name: 'CardNumber',
    bot_id: botIdValue,
    bot_version: 'DRAFT',
    locale_id: 'en_US',
    intent_id: 'TakePayment',
  };
  if (obfuscationSetting !== undefined) values['obfuscation_setting'] = obfuscationSetting;
  return {
    type: 'aws_lexv2models_slot',
    name: 'card_number',
    address: 'aws_lexv2models_slot.card_number',
    values,
  } as unknown as TerraformResource;
}

function runControl(slot: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'lex-project',
    resource: slot,
    allResources: [slot, ...allResources],
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 REQ-11 (Terraform): slot obfuscation disabled while bot logging is off', () => {
  it('flags a slot with obfuscation_setting_type "None" when the bot has no logging configured (reference form)', () => {
    const slot = buildSlot([{ obfuscation_setting_type: 'None' }], 'aws_lexv2models_bot.payment');

    const result = runControl(slot, [bot]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceType).toBe('aws_lexv2models_slot');
    expect(result?.resourceName).toBe('aws_lexv2models_slot.card_number');
    expect(result?.issue).toContain('CardNumber');
  });

  it('flags a slot with obfuscation_setting_type "None" when conversation logging is explicitly turned off on the alias (literal form)', () => {
    const slot = buildSlot([{ obfuscation_setting_type: 'None' }], 'bot-abc123');

    const result = runControl(slot, [bot, aliasLoggingOff]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.issue).toContain('CardNumber');
  });

  // Opposite outcome: same logging-off bot/alias, only the slot's obfuscation type changes.
  it('does not flag when the same logging-off bot has obfuscation enabled on the slot', () => {
    const slot = buildSlot([{ obfuscation_setting_type: 'DefaultObfuscation' }], 'aws_lexv2models_bot.payment');

    const result = runControl(slot, [bot, aliasLoggingOff]);

    expect(result).toBeNull();
  });
});
