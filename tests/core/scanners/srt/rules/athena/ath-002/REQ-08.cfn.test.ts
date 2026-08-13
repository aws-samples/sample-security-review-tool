import { describe, it, expect } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Template, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET_NAME = 'athena-results-bucket';
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/queries/`;

/**
 * Builds a template where the Athena workgroup writes results to a bucket whose
 * bucket policy carries a Deny statement gated on aws:SecureTransport.
 *
 * `secureTransportValue` controls the polarity of the condition:
 *  - 'false' => denies requests made WITHOUT TLS (the required control)
 *  - 'true'  => inverted: denies requests that DID use TLS, leaving plain HTTP allowed
 */
function buildTemplate(secureTransportValue: 'true' | 'false'): Template {
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
          BucketName: BUCKET_NAME,
        },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: BUCKET_NAME,
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'TransportCondition',
                Effect: 'Deny',
                Principal: '*',
                Action: 's3:*',
                Resource: [
                  `arn:aws:s3:::${BUCKET_NAME}`,
                  `arn:aws:s3:::${BUCKET_NAME}/*`,
                ],
                Condition: {
                  Bool: {
                    'aws:SecureTransport': secureTransportValue,
                  },
                },
              },
            ],
          },
        },
      },
    },
  } as unknown as Template;
}

function runWorkGroup(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const resource = resources['AnalyticsWorkGroup'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = new Ath002CfnAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 (CloudFormation) - inverted aws:SecureTransport condition on results bucket policy', () => {
  // Primary behavior owned by this requirement: a Deny gated on SecureTransport=true
  // is the inverse of the control and must be flagged.
  it('flags the workgroup when the results bucket policy denies requests that DO use secure transport', () => {
    const result = runWorkGroup(buildTemplate('true'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same policy with
  // the condition value corrected to 'false' (denying non-TLS requests).
  it('does not flag when the same Deny statement is correctly gated on aws:SecureTransport false', () => {
    const result = runWorkGroup(buildTemplate('false'));

    expect(result).toBeNull();
  });
});
