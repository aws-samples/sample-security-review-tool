import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildSlot(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name: 'card_number',
    address: 'aws_lexv2models_slot.card_number',
    values,
  } as TerraformResource;
}

function run(slot: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'lex-project',
    resource: slot,
    allResources: [slot],
  };
  const adapter = new Lex002TfAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 Terraform — REQ-03: slot with no value obfuscation configuration at all', () => {
  // Primary behavior owned by this requirement: obfuscation is opt-in, so a slot
  // declared with no obfuscation_setting block logs its values in cleartext -> flag.
  it('flags a slot that declares no obfuscation_setting block', () => {
    const result = run(buildSlot({
      name: 'CardNumber',
      bot_id: 'aws_lexv2models_bot.support',
      bot_version: 'DRAFT',
      intent_id: 'aws_lexv2models_intent.collect_payment',
      locale_id: 'en_US',
    }));

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-002');
    expect(result!.resourceType).toBe('aws_lexv2models_slot');
    expect(result!.resourceName).toBe('aws_lexv2models_slot.card_number');
    expect(result!.issue).toContain('CardNumber');
  });

  // Opposite outcome: identical slot, but with obfuscation explicitly configured
  // to the masking value -> no finding.
  it('does not flag a slot whose obfuscation_setting_type is DefaultObfuscation', () => {
    const result = run(buildSlot({
      name: 'CardNumber',
      bot_id: 'aws_lexv2models_bot.support',
      bot_version: 'DRAFT',
      intent_id: 'aws_lexv2models_intent.collect_payment',
      locale_id: 'en_US',
      obfuscation_setting: [{ obfuscation_setting_type: DEFAULT_OBFUSCATION }],
    }));

    expect(result).toBeNull();
  });
});
