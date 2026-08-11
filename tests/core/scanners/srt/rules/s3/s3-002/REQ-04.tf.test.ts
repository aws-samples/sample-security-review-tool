import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-04 (Terraform): A bucket policy Allow statement uses a wildcard
 * principal ("*") BUT includes a Condition constraining the effective
 * principal set to a trusted, identifiable audience (e.g. an org id, an
 * explicit PrincipalArn allow-list, a specific VPC endpoint, or a
 * specific source IP range).
 *
 * Expected: PASS — the grant is auditable and specific, so the control
 * must NOT produce a finding.
 */

const tfFactory = new S3002TfAdapterFactory();

function buildContext(policyDocument: unknown): TfContext {
  // aws_s3_bucket_policy carries the policy as a JSON-encoded string in the
  // plan (identical to what `jsonencode(...)` in HCL produces).
  const resource: TerraformResource = {
    type: 'aws_s3_bucket_policy',
    name: 'site',
    address: 'aws_s3_bucket_policy.site',
    values: {
      bucket: 'aws_s3_bucket.site',
      policy: JSON.stringify(policyDocument),
    },
  } as TerraformResource;

  return {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
}

function runControl(policyDocument: unknown) {
  const context = buildContext(policyDocument);
  const adapter = tfFactory.bind(context);
  return s3002Control.run(adapter, context);
}

describe('S3-002 REQ-04 (Terraform) — wildcard principal narrowed by a trusted condition passes', () => {
  it('passes when a wildcard principal is scoped by aws:PrincipalOrgID', () => {
    const result = runControl({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringEquals: { 'aws:PrincipalOrgID': 'o-abcd123456' },
          },
        },
      ],
    });
    expect(result).toBeNull();
  });

  it('passes when a wildcard principal is scoped by an explicit aws:PrincipalArn allow-list', () => {
    const result = runControl({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            ArnEquals: {
              'aws:PrincipalArn': [
                'arn:aws:iam::123456789012:role/TrustedRoleA',
                'arn:aws:iam::123456789012:role/TrustedRoleB',
              ],
            },
          },
        },
      ],
    });
    expect(result).toBeNull();
  });

  it('passes when a wildcard principal is scoped by a specific VPC endpoint', () => {
    const result = runControl({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringEquals: { 'aws:SourceVpce': 'vpce-0123456789abcdef0' },
          },
        },
      ],
    });
    expect(result).toBeNull();
  });

  it('passes when a wildcard principal is scoped by a specific source IP range', () => {
    const result = runControl({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            IpAddress: { 'aws:SourceIp': '203.0.113.0/24' },
          },
        },
      ],
    });
    expect(result).toBeNull();
  });

  /**
   * REQ-18 owns this verdict. These cases are the near-miss for REQ-04: a condition
   * is present, so an implementation that only checks whether a condition exists
   * would pass every test above and still pass these. The condition has to narrow
   * WHO may use the grant, not how they ask.
   */
  it('flags when the only condition constrains transport rather than identity', () => {
    const result = runControl({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            Bool: { 'aws:SecureTransport': 'true' },
          },
        },
      ],
    });
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
  });

  it('flags when the only condition constrains a canned ACL rather than identity', () => {
    const result = runControl({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringEquals: { 's3:x-amz-acl': 'bucket-owner-full-control' },
          },
        },
      ],
    });
    expect(result?.check_id).toBe('S3-002');
  });
});
