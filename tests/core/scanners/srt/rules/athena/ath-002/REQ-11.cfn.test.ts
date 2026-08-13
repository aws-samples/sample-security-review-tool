import { describe, expect, it } from 'vitest';

import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();

const SECURE_TRANSPORT_DENY = {
  Sid: 'DenyInsecureTransport',
  Effect: 'Deny',
  Principal: '*',
  Action: 's3:*',
  Resource: ['arn:aws:s3:::results-bucket', 'arn:aws:s3:::results-bucket/*'],
  Condition: { Bool: { 'aws:SecureTransport': 'false' } },
};

const UNRELATED_ALLOW = {
  Sid: 'AllowAnalysts',
  Effect: 'Allow',
  Principal: { AWS: 'arn:aws:iam::123456789012:root' },
  Action: 's3:GetObject',
  Resource: 'arn:aws:s3:::results-bucket/*',
};

function buildTemplate(statements: unknown): Template {
  return {
    Resources: {
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'results-bucket' },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: 'ResultsBucket',
          PolicyDocument: { Version: '2012-10-17', Statement: statements },
        },
      },
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: { OutputLocation: 's3://results-bucket/query-results/' },
          },
        },
      },
    },
  } as unknown as Template;
}

function runWorkGroup(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['AnalyticsWorkGroup'],
    logicalId: 'AnalyticsWorkGroup',
  };
  return ath002Control.run(factory.bind(context) as never, context);
}

describe('ATH-002 CloudFormation — secure-transport Deny hidden behind an unresolvable condition', () => {
  // Primary behavior owned by this requirement: indeterminate deciding value => no finding.
  it('does not flag when the Deny statement is selected by an Fn::If that cannot be resolved', () => {
    const template = buildTemplate([
      UNRELATED_ALLOW,
      { 'Fn::If': ['EnforceTlsCondition', SECURE_TRANSPORT_DENY, { Ref: 'AWS::NoValue' }] },
    ]);

    expect(runWorkGroup(template)).toBeNull();
  });

  it('does not flag when the entire policy document statement list is an unresolvable Fn::If', () => {
    const template = buildTemplate({
      'Fn::If': ['EnforceTlsCondition', [SECURE_TRANSPORT_DENY], [UNRELATED_ALLOW]],
    });

    expect(runWorkGroup(template)).toBeNull();
  });

  it('does not flag when the policy document itself comes from an unresolvable Fn::ImportValue', () => {
    const template = buildTemplate(undefined);
    const resources = (template.Resources ?? {}) as Record<string, any>;
    resources['ResultsBucketPolicy'].Properties.PolicyDocument = {
      'Fn::ImportValue': 'SharedResultsBucketPolicyDocument',
    };

    expect(runWorkGroup(template)).toBeNull();
  });

  // Opposite outcome: same fixture, but the deciding value IS resolvable and lacks the Deny.
  it('flags when the fully resolved policy contains no secure-transport Deny statement', () => {
    const template = buildTemplate([UNRELATED_ALLOW]);

    const result = runWorkGroup(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });
});
