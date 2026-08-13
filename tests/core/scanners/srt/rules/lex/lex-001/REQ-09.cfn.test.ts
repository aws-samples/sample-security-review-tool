import { describe, it, expect } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::Lex::Bot',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { MyBot: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: 'MyBot' };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = factory.bind(context) as unknown as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

// Other privacy/protection settings present, no child-directed declaration.
const OTHER_PROTECTIONS_ONLY = {
  Name: 'coppa-bot',
  RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
  IdleSessionTTLInSeconds: 300,
  TestBotAliasSettings: {
    ConversationLogSettings: {
      AudioLogSettings: [
        {
          Enabled: true,
          Destination: {
            S3Bucket: {
              S3BucketArn: 'arn:aws:s3:::conversation-logs',
              KmsKeyArn: 'arn:aws:kms:us-east-1:123456789012:key/abc',
              LogPrefix: 'audio/',
            },
          },
        },
      ],
      TextLogSettings: [
        {
          Enabled: true,
          Destination: {
            CloudWatch: {
              CloudWatchLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:lex',
              LogPrefix: 'text/',
            },
          },
        },
      ],
    },
  },
};

describe('LEX-001 CloudFormation - REQ-09: other protection settings do not substitute for the child-directed declaration', () => {
  // Primary behavior owned by this requirement: encryption/logging settings present but DataPrivacy missing -> flag.
  it('flags a bot that configures conversation log encryption/logging but omits DataPrivacy entirely', () => {
    const result = scan({ ...OTHER_PROTECTIONS_ONLY });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  it('flags a bot with logging settings and a DataPrivacy block that omits ChildDirected', () => {
    const result = scan({ ...OTHER_PROTECTIONS_ONLY, DataPrivacy: {} });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  // Opposite outcome: identical fixture except the child-directed declaration is present and true.
  it('does not flag the same bot once ChildDirected is explicitly true', () => {
    const result = scan({ ...OTHER_PROTECTIONS_ONLY, DataPrivacy: { ChildDirected: true } });

    expect(result).toBeNull();
  });
});
