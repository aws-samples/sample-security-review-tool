import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 Terraform - REQ-06: dangling OAC reference', () => {
  it('flags an S3 origin whose origin_access_control_id does not resolve to any aws_cloudfront_origin_access_control resource in the project', () => {
    // The distribution's S3 origin sets origin_access_control_id to a value
    // that does not match the id of any aws_cloudfront_origin_access_control
    // resource present in allResources. This is a dangling reference and
    // must be flagged per the resolved decision.
    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      mode: 'managed',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'my-s3-origin',
            domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
            // Points at an OAC id that no aws_cloudfront_origin_access_control
            // resource in this project actually produces.
            origin_access_control_id: 'oac-does-not-exist-12345',
            s3_origin_config: [{}],
          },
        ],
      },
    } as unknown as TerraformResource;

    // No aws_cloudfront_origin_access_control resource exists in the project.
    const allResources: TerraformResource[] = [distribution];

    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
