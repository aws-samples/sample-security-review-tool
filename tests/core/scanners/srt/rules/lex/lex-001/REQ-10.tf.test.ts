import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001TfAdapterFactory();

function run(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

const v2Bot = (values: Record<string, unknown>): TerraformResource => ({
  type: 'aws_lexv2models_bot',
  name: 'child_bot',
  address: 'aws_lexv2models_bot.child_bot',
  values,
} as unknown as TerraformResource);

describe('LEX-001 Terraform - child-directed declared only on a related resource', () => {
  // REQ-10 (primary): declaration on a locale resource that references the bot does not satisfy the bot.
  it('flags aws_lexv2models_bot when child_directed is declared on a referencing locale resource', () => {
    const bot = v2Bot({ name: 'child-bot', idle_session_ttl_in_seconds: 300 });
    const locale: TerraformResource = {
      type: 'aws_lexv2models_bot_locale',
      name: 'en_us',
      address: 'aws_lexv2models_bot_locale.en_us',
      values: {
        bot_id: 'aws_lexv2models_bot.child_bot',
        locale_id: 'en_US',
        data_privacy: [{ child_directed: true }],
      },
    } as unknown as TerraformResource;

    const result = run(bot, [bot, locale]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.child_bot');
  });

  // REQ-10 (primary): declaration on a bot alias does not satisfy the classic bot resource.
  it('flags aws_lex_bot when child_directed is declared on a referencing bot alias resource', () => {
    const bot: TerraformResource = {
      type: 'aws_lex_bot',
      name: 'classic',
      address: 'aws_lex_bot.classic',
      values: { name: 'classic-bot' },
    } as unknown as TerraformResource;
    const alias: TerraformResource = {
      type: 'aws_lex_bot_alias',
      name: 'prod',
      address: 'aws_lex_bot_alias.prod',
      values: { bot_name: 'aws_lex_bot.classic', child_directed: true },
    } as unknown as TerraformResource;

    const result = run(bot, [bot, alias]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('aws_lex_bot.classic');
  });

  // Opposite outcome: identical setup, but the declaration lives on the bot itself.
  it('does not flag aws_lexv2models_bot that declares child_directed true on the bot resource', () => {
    const bot = v2Bot({
      name: 'child-bot',
      idle_session_ttl_in_seconds: 300,
      data_privacy: [{ child_directed: true }],
    });
    const locale: TerraformResource = {
      type: 'aws_lexv2models_bot_locale',
      name: 'en_us',
      address: 'aws_lexv2models_bot_locale.en_us',
      values: {
        bot_id: 'aws_lexv2models_bot.child_bot',
        locale_id: 'en_US',
        data_privacy: [{ child_directed: true }],
      },
    } as unknown as TerraformResource;

    expect(run(bot, [bot, locale])).toBeNull();
  });
});
