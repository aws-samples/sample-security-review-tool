import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.tf.js';
import { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002TfAdapterFactory();

/**
 * In Terraform, a slot is its own resource (aws_lexv2models_slot). A bot that defines
 * no slots therefore shows up as a plan containing bot / locale / intent resources but
 * no slot resources at all, so we scan the whole plan rather than a single resource.
 */
function scanPlan(resources: TerraformResource[]): ScanResult[] {
  const findings: ScanResult[] = [];
  for (const resource of resources) {
    if (!factory.appliesTo(resource.type)) continue;
    const context: TfContext = { projectName: 'test-project', resource, allResources: resources };
    const result = lex002Control.run(factory.bind(context), context);
    if (result) findings.push(result);
  }
  return findings;
}

const bot: TerraformResource = {
  type: 'aws_lexv2models_bot',
  name: 'order_bot',
  address: 'aws_lexv2models_bot.order_bot',
  values: { name: 'OrderBot', idle_session_ttl_in_seconds: 300 },
} as unknown as TerraformResource;

const locale: TerraformResource = {
  type: 'aws_lexv2models_bot_locale',
  name: 'en_us',
  address: 'aws_lexv2models_bot_locale.en_us',
  // Reference form: locale wired to the bot resource by reference in HCL.
  values: { bot_id: 'aws_lexv2models_bot.order_bot', locale_id: 'en_US', n_lu_intent_confidence_threshold: 0.4 },
} as unknown as TerraformResource;

const intent: TerraformResource = {
  type: 'aws_lexv2models_intent',
  name: 'greet',
  address: 'aws_lexv2models_intent.greet',
  // Reference form: intent wired to the bot and locale resources by reference in HCL.
  values: {
    name: 'GreetIntent',
    bot_id: 'aws_lexv2models_bot.order_bot',
    locale_id: 'aws_lexv2models_bot_locale.en_us',
  },
} as unknown as TerraformResource;

describe('LEX-002 Terraform - bots with no slots to evaluate (REQ-12)', () => {
  it('does not report a finding when the plan defines a bot with no slot resources', () => {
    expect(scanPlan([bot])).toEqual([]);
  });

  it('does not report a finding when locales and intents exist but define an empty set of slots', () => {
    expect(scanPlan([bot, locale, intent])).toEqual([]);
  });

  // Opposite outcome: the primary "obfuscation must be enabled" behavior is owned by the
  // main LEX-002 requirement. Included here to prove the passes above are caused by the
  // absence of slot resources and not by a control that never reports anything.
  it('reports a finding when the same bot does define a slot with obfuscation disabled', () => {
    const slot: TerraformResource = {
      type: 'aws_lexv2models_slot',
      name: 'card_number',
      address: 'aws_lexv2models_slot.card_number',
      values: {
        name: 'CardNumber',
        bot_id: 'aws_lexv2models_bot.order_bot',
        intent_id: 'aws_lexv2models_intent.greet',
        locale_id: 'aws_lexv2models_bot_locale.en_us',
        obfuscation_setting: [{ obfuscation_setting_type: 'None' }],
      },
    } as unknown as TerraformResource;

    const findings = scanPlan([bot, locale, intent, slot]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.check_id).toBe('LEX-002');
    expect(findings[0]?.issue).toContain('CardNumber');
  });
});
