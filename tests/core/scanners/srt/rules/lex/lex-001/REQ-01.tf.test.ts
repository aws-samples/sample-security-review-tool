import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001TfAdapterFactory();

function run(resource: TerraformResource, allResources: TerraformResource[] = [resource]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context);
  return lex001Control.run(adapter, context);
}

describe('LEX-001 (Terraform) - DataPrivacy child-directed must be explicitly true', () => {
  // Primary behavior owned by this requirement: no data privacy configuration at all => flag.
  it('flags an aws_lexv2models_bot defined without any data_privacy block', () => {
    const bot: TerraformResource = {
      type: 'aws_lexv2models_bot',
      name: 'order_bot',
      address: 'aws_lexv2models_bot.order_bot',
      values: {
        name: 'order-bot',
        role_arn: 'arn:aws:iam::123456789012:role/lex-role',
        idle_session_ttl_in_seconds: 300,
      },
    } as unknown as TerraformResource;

    const result = run(bot);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('aws_lexv2models_bot');
    expect(result?.resourceName).toBe('aws_lexv2models_bot.order_bot');
  });

  it('flags an aws_lex_bot defined without any child_directed declaration', () => {
    const bot: TerraformResource = {
      type: 'aws_lex_bot',
      name: 'legacy_bot',
      address: 'aws_lex_bot.legacy_bot',
      values: {
        name: 'legacy-bot',
        idle_session_ttl_in_seconds: 300,
      },
    } as unknown as TerraformResource;

    const result = run(bot);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('aws_lex_bot');
  });

  // Opposite outcome: same bots, but the child-directed declaration is present and true => no finding.
  it('does not flag an aws_lexv2models_bot whose data_privacy child_directed is explicitly true', () => {
    const bot: TerraformResource = {
      type: 'aws_lexv2models_bot',
      name: 'order_bot',
      address: 'aws_lexv2models_bot.order_bot',
      values: {
        name: 'order-bot',
        role_arn: 'arn:aws:iam::123456789012:role/lex-role',
        idle_session_ttl_in_seconds: 300,
        data_privacy: [{ child_directed: true }],
      },
    } as unknown as TerraformResource;

    expect(run(bot)).toBeNull();
  });

  it('does not flag an aws_lex_bot whose child_directed is explicitly true', () => {
    const bot: TerraformResource = {
      type: 'aws_lex_bot',
      name: 'legacy_bot',
      address: 'aws_lex_bot.legacy_bot',
      values: {
        name: 'legacy-bot',
        idle_session_ttl_in_seconds: 300,
        child_directed: true,
      },
    } as unknown as TerraformResource;

    expect(run(bot)).toBeNull();
  });
});
