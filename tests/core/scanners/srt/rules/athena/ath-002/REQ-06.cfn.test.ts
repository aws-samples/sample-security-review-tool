import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (ATH-002): the secure-transport Deny on the Athena results bucket must cover
 * bucket-level operations as well as object-level ones. A Deny scoped only to
 * "arn:aws:s3:::bucket/*" leaves bucket-level calls reachable over plain HTTP => flag.
 */

const BUCKET_NAME = 'athena-results-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET_NAME}`;
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/results/`;

function denyStatement(resource: unknown): Record<string, unknown> {
  return {
    Sid: 'DenyInsecureTransport',
    Effect: 'Deny',
    Principal: '*',
    Action: 's3:*',
    Resource: resource,
    Condition: { Bool: { 'aws:SecureTransport': 'false' } },
  };
}

function buildTemplate(denyResourceScope: unknown): Template {
  return {
    Resources: {
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: BUCKET_NAME },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          // !Ref ResultsBucket resolves to the logical id string after preprocessing
          Bucket: 'ResultsBucket',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [denyStatement(denyResourceScope)],
          },
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

function runControl(template: Template, logicalId = 'AnalyticsWorkGroup'): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const resource = resources[logicalId];
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = new Ath002CfnAdapterFactory().bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-06 (CloudFormation): secure-transport Deny scope must cover the bucket itself', () => {
  it('flags a workgroup whose results-bucket Deny is scoped only to the objects inside the bucket', () => {
    const result = runControl(buildTemplate(`${BUCKET_ARN}/*`));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.issue).toMatch(/TLS/i);
  });

  it('flags an object-only Deny expressed as a single-element Resource array', () => {
    const result = runControl(buildTemplate([`${BUCKET_ARN}/*`]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical fixture except the Deny scope also covers the bucket ARN.
  it('does not flag when the Deny scope covers both the bucket ARN and the object ARN', () => {
    const result = runControl(buildTemplate([BUCKET_ARN, `${BUCKET_ARN}/*`]));

    expect(result).toBeNull();
  });
});
