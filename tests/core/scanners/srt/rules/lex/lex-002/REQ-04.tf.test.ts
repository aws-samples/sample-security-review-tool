import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT_NAME = 'lex-project';

function buildSlot(obfuscationSetting: unknown): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name: 'card_number',
    address: 'aws_lexv2models_slot.card_number',
    values: {
      name: 'CardNumber',
      bot_id: 'aws_lexv2models_bot.support',
      intent_id: 'aws_lexv2models_intent.collect_card',
      obfuscation_setting: obfuscationSetting,
    },
  } as unknown as TerraformResource;
}

function run(obfuscationSetting: unknown): ScanResult | null {
  const resource = buildSlot(obfuscationSetting);
  const context: TfContext = {
    projectName: PROJECT_NAME,
    resource,
    allResources: [resource],
  };
  const adapter = new Lex002TfAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 Terraform - REQ-04: obfuscation configuration present without a type value', () => {
  // Primary behavior owned by REQ-04: an obfuscation_setting block with no
  // obfuscation_setting_type provides no evidence of masking and must be flagged.
  it('flags a slot whose obfuscation_setting block carries no obfuscation_setting_type', () => {
    const result = run([{}]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe('aws_lexv2models_slot.card_number');
    expect(result?.resourceType).toBe('aws_lexv2models_slot');
    expect(result?.issue).toContain('CardNumber');
  });

  it('flags a slot whose obfuscation_setting_type is present but null', () => {
    const result = run([{ obfuscation_setting_type: null }]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
  });

  // Opposite outcome: same structure, but the type value is present and selects masking.
  it('does not flag a slot whose obfuscation_setting block carries DefaultObfuscation', () => {
    const result = run([{ obfuscation_setting_type: DEFAULT_OBFUSCATION }]);

    expect(result).toBeNull();
  });
});
