import { describe, it, expect } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001TfAdapterFactory();

function scan(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as unknown as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

// Other privacy/protection settings (encryption, conversation logging) but no child-directed declaration.
const V2_OTHER_PROTECTIONS_ONLY: Record<string, unknown> = {
  name: 'coppa-bot',
  role_arn: 'arn:aws:iam::123456789012:role/lex-role',
  idle_session_ttl_in_seconds: 300,
  test_bot_alias_settings: [
    {
      conversation_log_settings: [
        {
          audio_log_settings: [
            {
              enabled: true,
              destination: [
                {
                  s3_bucket: [
                    {
                      s3_bucket_arn: 'arn:aws:s3:::conversation-logs',
                      kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/abc',
                      log_prefix: 'audio/',
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
  ],
};

function v2Bot(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_lexv2models_bot',
    name: 'coppa',
    address: 'aws_lexv2models_bot.coppa',
    values,
  } as unknown as TerraformResource;
}

describe('LEX-001 Terraform - REQ-09: other protection settings do not substitute for the child-directed declaration', () => {
  // Primary behavior owned by this requirement.
  it('flags aws_lexv2models_bot with conversation log encryption but no data_privacy block', () => {
    const result = scan(v2Bot({ ...V2_OTHER_PROTECTIONS_ONLY }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  it('flags aws_lexv2models_bot whose data_privacy block omits child_directed', () => {
    const result = scan(v2Bot({ ...V2_OTHER_PROTECTIONS_ONLY, data_privacy: [{}] }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  it('flags aws_lex_bot that sets encryption/logging related settings but omits child_directed', () => {
    const result = scan({
      type: 'aws_lex_bot',
      name: 'classic',
      address: 'aws_lex_bot.classic',
      values: {
        name: 'classic-bot',
        process_behavior: 'BUILD',
        idle_session_ttl_in_seconds: 300,
        detect_sentiment: true,
      },
    } as unknown as TerraformResource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  // Opposite outcome: identical fixture except the child-directed declaration is present and true.
  it('does not flag the same aws_lexv2models_bot once child_directed is true', () => {
    const result = scan(v2Bot({ ...V2_OTHER_PROTECTIONS_ONLY, data_privacy: [{ child_directed: true }] }));

    expect(result).toBeNull();
  });
});
