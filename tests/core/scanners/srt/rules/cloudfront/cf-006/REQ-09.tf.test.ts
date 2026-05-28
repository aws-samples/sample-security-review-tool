import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 Terraform - REQ-09: multiple origins where one S3 origin lacks OAC/OAI', () => {
  it('flags the distribution when one of multiple S3 origins is unprotected while others are secured', () => {
    const oacResource: any = {
      address: 'aws_cloudfront_origin_access_control.secure',
      type: 'aws_cloudfront_origin_access_control',
      name: 'secure',
      values: {
        id: 'oac-secure-id',
        name: 'secure-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
      },
    };

    const distributionResource: any = {
      address: 'aws_cloudfront_distribution.this',
      type: 'aws_cloudfront_distribution',
      name: 'this',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'secured-by-oac',
            domain_name: 'secured-by-oac.s3.us-east-1.amazonaws.com',
            origin_access_control_id: 'oac-secure-id',
            s3_origin_config: [],
          },
          {
            origin_id: 'secured-by-oai',
            domain_name: 'secured-by-oai.s3.us-east-1.amazonaws.com',
            s3_origin_config: [
              { origin_access_identity: 'origin-access-identity/cloudfront/E1234567890ABC' },
            ],
          },
          {
            origin_id: 'unprotected-s3',
            domain_name: 'unprotected-s3.s3.us-east-1.amazonaws.com',
            s3_origin_config: [{}],
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: distributionResource,
      allResources: [distributionResource, oacResource],
    };

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.status).toBe('Open');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.this');
    expect(result?.issue).toContain('S3 bucket origin');
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('unprotected-s3');
  });
});
