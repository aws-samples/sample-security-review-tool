import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (ATH-002): When the Athena workgroup's query-result output location cannot be
 * resolved at analysis time (it derives from an externally supplied / unresolvable value),
 * the rule cannot identify the results bucket and must NOT report a finding.
 */

const factory = new Ath002CfnAdapterFactory();

const NON_TLS_POLICY_DOCUMENT = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AllowReads',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::123456789012:root' },
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::athena-results/*',
    },
  ],
};

function buildTemplate(outputLocation: unknown): Template {
  return {
    Resources: {
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'athena-results' },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: 'ResultsBucket',
          PolicyDocument: NON_TLS_POLICY_DOCUMENT,
        },
      },
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              OutputLocation: outputLocation,
            },
          },
        },
      },
    },
  } as unknown as Template;
}

function runWorkGroup(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['AnalyticsWorkGroup'],
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 CloudFormation — unresolvable query-result output location', () => {
  it('produces no finding when the output location comes from an unresolved Fn::ImportValue', () => {
    const template = buildTemplate({ 'Fn::ImportValue': 'SharedAthenaResultsLocation' });

    expect(runWorkGroup(template)).toBeNull();
  });

  it('produces no finding when the output location is an unresolved Fn::If', () => {
    const template = buildTemplate({
      'Fn::If': ['UseSharedBucket', 's3://shared-results/queries/', 's3://athena-results/queries/'],
    });

    expect(runWorkGroup(template)).toBeNull();
  });

  it('produces no finding when the output location is an opaque Fn::Join over unresolved parts', () => {
    const template = buildTemplate({
      'Fn::Join': ['', ['s3://', { 'Fn::ImportValue': 'SharedResultsBucketName' }, '/queries/']],
    });

    expect(runWorkGroup(template)).toBeNull();
  });

  // Opposite outcome — owned by the "output bucket allows insecure transport" requirement.
  // Only the resolvability of the output location changes: here it is a resolved literal
  // pointing at a bucket whose policy does not deny non-TLS requests, so a finding IS produced.
  it('reports a finding when the same output location resolves to a bucket lacking a TLS-enforcing policy', () => {
    const template = buildTemplate('s3://athena-results/queries/');

    const result = runWorkGroup(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });
});
