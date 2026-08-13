import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import { DEFAULT_OBFUSCATION, NONE_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002TfAdapterFactory();

function slot(name: string, obfuscationType: string): TerraformResource {
  return {
    type: 'aws_lexv2models_slot',
    name,
    address: `aws_lexv2models_slot.${name}`,
    values: {
      name,
      // reference form: bot_id wired from another resource collapses to its address
      bot_id: 'aws_lexv2models_bot.support',
      bot_version: 'DRAFT',
      locale_id: 'en_US',
      intent_id: 'aws_lexv2models_intent.collect_payment',
      obfuscation_setting: [{ obfuscation_setting_type: obfuscationType }],
    },
  } as unknown as TerraformResource;
}

function run(assessed: TerraformResource, all: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: assessed,
    allResources: all,
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 REQ-10 (Terraform): obfuscation on a different slot resource does not cover the assessed slot', () => {
  // Primary behavior owned by this requirement.
  it('flags the assessed slot when a sibling slot of the same bot is obfuscated but the assessed slot is not', () => {
    const obfuscated = slot('card_number', DEFAULT_OBFUSCATION);
    const assessed = slot('security_code', NONE_OBFUSCATION);

    const result = run(assessed, [obfuscated, assessed]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe('aws_lexv2models_slot.security_code');
    expect(result?.issue).toContain('security_code');
    expect(result?.issue).not.toContain('card_number');
  });

  // Opposite outcome: same wiring, but the assessed slot itself obfuscates its values.
  it('does not flag the assessed slot when it has obfuscation enabled even though a sibling slot disables it', () => {
    const unobfuscatedSibling = slot('card_number', NONE_OBFUSCATION);
    const assessed = slot('security_code', DEFAULT_OBFUSCATION);

    const result = run(assessed, [unobfuscatedSibling, assessed]);

    expect(result).toBeNull();
  });
});
