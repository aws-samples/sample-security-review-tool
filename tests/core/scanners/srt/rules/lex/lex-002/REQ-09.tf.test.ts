import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildSlot(obfuscationSettingType: string): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name: 'card_number',
    address: 'aws_lexv2models_slot.card_number',
    values: {
      name: 'CardNumber',
      bot_id: 'aws_lexv2models_bot.support',
      locale_id: 'en_US',
      intent_id: 'CollectPayment',
      obfuscation_setting: [
        { obfuscation_setting_type: obfuscationSettingType },
      ],
    },
  } as unknown as TerraformResource;
}

function run(obfuscationSettingType: string) {
  const resource = buildSlot(obfuscationSettingType);
  const context: TfContext = {
    projectName: 'lex-project',
    resource,
    allResources: [resource],
  };
  const adapter = new Lex002TfAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 Terraform - unrecognized non-disabled obfuscation type', () => {
  // Primary behavior owned by REQ-09: only the none/disabled value turns off
  // masking, so an obfuscation type the rule does not specifically recognize
  // must be treated as compliant.
  it('passes when the slot uses an unrecognized obfuscation type', () => {
    expect(run('FutureObfuscation')).toBeNull();
  });

  it('passes when the slot uses another unrecognized obfuscation type', () => {
    expect(run('PartialObfuscation')).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is the
  // none/disabled obfuscation type, which LEX-002 must flag.
  it('flags the slot when the obfuscation type is the none/disabled value', () => {
    const result = run('None');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe('aws_lexv2models_slot.card_number');
    expect(result?.issue).toContain('CardNumber');
  });
});
