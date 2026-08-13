import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (ATH-002): An Athena workgroup whose results bucket has a bucket policy
 * attached, but whose policy document contains no statements at all, must be flagged.
 * An empty statement list contains no secure-transport Deny, so plaintext HTTP is unblocked.
 */

const OUTPUT_LOCATION = 's3://athena-results-bucket/queries/';

function buildTemplate(policyStatements: unknown[]): Template {
  return {
    Resources: {
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              OutputLocation: OUTPUT_LOCATION,
            },
          },
        },
      },
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'athena-results-bucket',
        },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          // !Ref ResultsBucket resolves to the logical id string after preprocessing
          Bucket: 'ResultsBucket',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: policyStatements,
          },
        },
      },
    },
  } as unknown as Template;
}

const SECURE_TRANSPORT_DENY = {
  Sid: 'DenyInsecureTransport',
  Effect: 'Deny',
  Principal: '*',
  Action: 's3:*',
  Resource: [
    'arn:aws:s3:::athena-results-bucket',
    'arn:aws:s3:::athena-results-bucket/*',
  ],
  Condition: {
    Bool: {
      'aws:SecureTransport': 'false',
    },
  },
};

function runOnWorkGroup(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const resource = resources['AnalyticsWorkGroup'];
  const context: CfnContext = {
    stackName: 'analytics-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = new Ath002CfnAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-13 (CloudFormation): results bucket policy with no statements', () => {
  it('flags the workgroup when the attached bucket policy has an empty statement list', () => {
    const result = runOnWorkGroup(buildTemplate([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });

  // Opposite outcome: identical template except the policy carries the secure-transport Deny.
  it('does not flag the workgroup when the same policy contains a secure-transport Deny statement', () => {
    const result = runOnWorkGroup(buildTemplate([SECURE_TRANSPORT_DENY]));

    expect(result).toBeNull();
  });
});
