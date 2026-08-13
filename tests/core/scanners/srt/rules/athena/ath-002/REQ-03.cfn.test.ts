import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();

function scan(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources ?? {})[logicalId] as Resource;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  return ath002Control.run(factory.bind(context), context);
}

const OUTPUT_LOCATION = 's3://athena-results-bucket/queries/';

/** The AWS-documented "restrict access to only HTTPS requests" bucket policy statement. */
const denyInsecureTransportStatement = {
  Sid: 'DenyInsecureTransport',
  Effect: 'Deny',
  Principal: '*',
  Action: 's3:*',
  Resource: ['arn:aws:s3:::athena-results-bucket', 'arn:aws:s3:::athena-results-bucket/*'],
  Condition: { Bool: { 'aws:SecureTransport': 'false' } },
};

function buildTemplate(policyStatement: Record<string, unknown>): Template {
  return {
    Resources: {
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'athena-results-bucket' },
      },
      // { Ref: 'ResultsBucket' } resolves to the logical id string after preprocessing.
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: 'ResultsBucket',
          PolicyDocument: { Version: '2012-10-17', Statement: [policyStatement] },
        },
      },
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: { OutputLocation: OUTPUT_LOCATION },
          },
        },
      },
    },
  } as unknown as Template;
}

describe('ATH-002 REQ-03 (CloudFormation): workgroup results bucket policy denies non-TLS requests', () => {
  it('passes when the output bucket policy denies all principals and actions unless secure transport is used', () => {
    // Primary behavior owned by this requirement: Deny + Principal * + s3:* + aws:SecureTransport false => pass.
    expect(scan(buildTemplate(denyInsecureTransportStatement), 'AnalyticsWorkGroup')).toBeNull();
  });

  it('OPPOSITE: flags the workgroup when the same policy statement is conditioned on secure transport being true (no TLS enforcement)', () => {
    const template = buildTemplate({
      ...denyInsecureTransportStatement,
      Condition: { Bool: { 'aws:SecureTransport': 'true' } },
    });

    const result = scan(template, 'AnalyticsWorkGroup');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });
});
