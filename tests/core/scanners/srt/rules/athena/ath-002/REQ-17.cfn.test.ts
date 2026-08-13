import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-17 (ATH-002): When an Athena workgroup writes query results to an S3 bucket that is not
 * defined anywhere in the assessed template, the bucket's policy is not resolvable at analysis
 * time, so the control must pass (no finding).
 */

const factory = new Ath002CfnAdapterFactory();

function workGroup(outputLocation: string): Resource {
  return {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: outputLocation,
        },
      },
    },
  } as unknown as Resource;
}

function scan(resources: Record<string, Resource>): ScanResult | null {
  const template = { Resources: resources } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['AnalyticsWorkGroup'],
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-17 (CloudFormation): output bucket external to the template', () => {
  it('passes when the query-results bucket is not defined in the assessed template', () => {
    const result = scan({
      AnalyticsWorkGroup: workGroup('s3://external-results-bucket/queries/'),
    });

    expect(result).toBeNull();
  });

  it('passes when the external bucket is referenced by name only and no S3 resources exist at all', () => {
    const result = scan({
      AnalyticsWorkGroup: workGroup('s3://another-account-results-bucket/'),
      SomeUnrelatedTopic: { Type: 'AWS::SNS::Topic', Properties: {} } as unknown as Resource,
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is the SAME workgroup whose
  // results bucket IS defined in the template with an inspectable policy that fails to deny
  // non-TLS requests. Primary ownership of this flagging behaviour belongs to ATH-002's
  // 'output-bucket-allows-insecure-transport' scenario.
  it('flags the workgroup when the results bucket is defined in the template and its policy does not enforce TLS', () => {
    const result = scan({
      AnalyticsWorkGroup: workGroup('s3://internal-results-bucket/queries/'),
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'internal-results-bucket' },
      } as unknown as Resource,
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: 'ResultsBucket',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { AWS: 'arn:aws:iam::123456789012:root' },
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::internal-results-bucket/*',
              },
            ],
          },
        },
      } as unknown as Resource,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });
});
