import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * ATH-002 / REQ-04
 * Requirement: an Athena workgroup passes when its S3 output-location bucket is covered by a
 * bucket-policy Deny statement enforcing aws:SecureTransport. This file owns the case where the
 * Deny statement's action and resource scopes are broad wildcards that encompass the bucket and
 * all of its objects -- at least as restrictive as an enumerated scope, therefore a pass.
 */

const factory = new Ath002CfnAdapterFactory();

const BUCKET_NAME = 'athena-results-bucket';
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/query-results/`;

function wildcardDenyStatement(secureTransportValue: string): Record<string, unknown> {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyInsecureTransport',
        Effect: 'Deny',
        Principal: '*',
        Action: '*',
        Resource: '*',
        Condition: { Bool: { 'aws:SecureTransport': secureTransportValue } },
      },
    ],
  };
}

function buildTemplate(policyDocument: Record<string, unknown>): Template {
  return {
    Resources: {
      AthenaWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: { OutputLocation: OUTPUT_LOCATION },
          },
        },
      },
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: BUCKET_NAME },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          // !Ref ResultsBucket resolves to the logical id after preprocessing
          Bucket: 'ResultsBucket',
          PolicyDocument: policyDocument,
        },
      },
    },
  } as unknown as Template;
}

function runWorkGroup(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'analytics-stack',
    template,
    resource: resources['AthenaWorkGroup'],
    logicalId: 'AthenaWorkGroup',
  };
  return ath002Control.run(factory.bind(context), context);
}

describe('ATH-002 REQ-04 (CloudFormation): wildcard-scoped Deny on non-TLS requests', () => {
  it('passes when the Deny statement uses wildcard action and resource scopes with aws:SecureTransport false', () => {
    const result = runWorkGroup(buildTemplate(wildcardDenyStatement('false')));

    expect(result).toBeNull();
  });

  it('OPPOSITE: flags when the same wildcard Deny statement is conditioned on secure transport being true (does not enforce TLS)', () => {
    const result = runWorkGroup(buildTemplate(wildcardDenyStatement('true')));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AthenaWorkGroup');
  });
});
